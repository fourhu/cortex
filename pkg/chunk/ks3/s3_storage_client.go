package ks3

import (
	"context"
	"crypto/tls"
	"flag"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	ks3aws "github.com/ks3sdklib/aws-sdk-go/aws"
	ks3credentials "github.com/ks3sdklib/aws-sdk-go/aws/credentials"
	ks3 "github.com/ks3sdklib/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/weaveworks/common/instrument"
	"os"

	"github.com/cortexproject/cortex/pkg/chunk"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

const (
	SignatureVersionV4 = "v4"
	SignatureVersionV2 = "v2"
)

var (
	supportedSignatureVersions     = []string{SignatureVersionV4, SignatureVersionV2}
	errUnsupportedSignatureVersion = errors.New("unsupported signature version")
)

var (
	ks3RequestDuration = instrument.NewHistogramCollector(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "cortex",
		Name:      "ks3_request_duration_seconds",
		Help:      "Time spent doing S3 requests.",
		Buckets:   []float64{.025, .05, .1, .25, .5, 1, 2},
	}, []string{"operation", "status_code"}))
)

// InjectRequestMiddleware gives users of this client the ability to make arbitrary
// changes to outgoing requests.
type InjectRequestMiddleware func(next http.RoundTripper) http.RoundTripper

func init() {
	ks3RequestDuration.Register()
}

// S3Config specifies config for storing chunks on AWS S3.
type KS3Config struct {
	S3                      flagext.URLValue
	AccessKeyID             string `yaml:"access_key_id"`
	SecretAccessKey         string `yaml:"secret_access_key"`
	BucketNames             string `yaml:"bucketNames"`
	Credentials             *ks3credentials.Credentials
	Endpoint                string `yaml:"endpoint"`
	Region                  string `yaml:"region"`
	DisableSSL              bool   `yaml:"disableSSL"`
	ManualSend              bool   `yaml:"manualSend"`
	HTTPClient              *http.Client
	LogHTTPBody             bool `yaml:"logHTTPBody"`
	LogLevel                uint `yaml:"logLevel"`
	Logger                  io.Writer
	HTTPConfig              HTTPConfig              `yaml:"http_config"`
	MaxRetries              int                     `yaml:"maxRetries"`
	DisableParamValidation  bool                    `yaml:"disableParamValidation"`
	DisableComputeChecksums bool                    `yaml:"disableComputeChecksums"`
	S3ForcePathStyle        bool                    `yaml:"s3ForcePathStyle"`
	Inject                  InjectRequestMiddleware `yaml:"-"`
}

// HTTPConfig stores the http.Transport configuration
type HTTPConfig struct {
	IdleConnTimeout       time.Duration `yaml:"idle_conn_timeout"`
	ResponseHeaderTimeout time.Duration `yaml:"response_header_timeout"`
	InsecureSkipVerify    bool          `yaml:"insecure_skip_verify"`
	TLSHandshakeTimeout   time.Duration `yaml:"tls_handshake_timeout"`
}

// RegisterFlags adds the flags required to config this to the given FlagSet
func (cfg *KS3Config) RegisterFlags(f *flag.FlagSet) {
	cfg.RegisterFlagsWithPrefix("", f)
}

// RegisterFlagsWithPrefix adds the flags required to config this to the given FlagSet with a specified prefix
func (cfg *KS3Config) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.Var(&cfg.S3, prefix+"ks3.url", "S3 endpoint URL with escaped Key and Secret encoded. "+
		"If only region is specified as a host, proper endpoint will be deduced. Use inmemory:///<bucket-name> to use a mock in-memory implementation.")
	f.BoolVar(&cfg.S3ForcePathStyle, prefix+"ks3.force-path-style", false, "Set this to `true` to force the request to use path-style addressing.")
	f.StringVar(&cfg.BucketNames, prefix+"ks3.bucketNames", "", "Comma separated list of bucket names to evenly distribute chunks over. Overrides any buckets specified in s3.url flag")
	f.StringVar(&cfg.Endpoint, prefix+"ks3.endpoint", "", "S3 Endpoint to connect to.")
	f.StringVar(&cfg.Region, prefix+"ks3.region", "", "AWS region to use.")
	f.StringVar(&cfg.AccessKeyID, prefix+"ks3.access-key-id", "", "AWS Access Key ID")
	f.StringVar(&cfg.SecretAccessKey, prefix+"ks3.secret-access-key", "", "AWS Secret Access Key")
	f.BoolVar(&cfg.DisableSSL, prefix+"ks3.disableSSL", false, "Disable https on s3 connection.")
	f.UintVar(&cfg.LogLevel, prefix+"ks3.logLevel", 1, "wether open log, 0: disable, 1 enable")

	f.DurationVar(&cfg.HTTPConfig.IdleConnTimeout, prefix+"ks3.http.idle-conn-timeout", 90*time.Second, "The maximum amount of time an idle connection will be held open.")
	f.DurationVar(&cfg.HTTPConfig.ResponseHeaderTimeout, prefix+"ks3.http.response-header-timeout", 0, "If non-zero, specifies the amount of time to wait for a server's response headers after fully writing the request.")
	f.BoolVar(&cfg.HTTPConfig.InsecureSkipVerify, prefix+"ks3.http.insecure-skip-verify", false, "Set to false to skip verifying the certificate chain and hostname.")
}

// Validate config and returns error on failure
func (cfg *KS3Config) Validate() error {
	return nil
}

type S3ObjectClient struct {
	bucketNames []string
	//S3          s3iface.S3API
	//KS3			*ks3s3iface.S3API
	KS3 *ks3.S3
	//sseConfig   *SSEParsedConfig
}

// NewKS3ObjectClient makes a new S3-backed ObjectClient.
func NewKS3ObjectClient(cfg KS3Config) (*S3ObjectClient, error) {
	ks3Config, bucketNames, err := buildKS3Config(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build s3 config")
	}

	ks3Client := ks3.New(ks3Config)
	client := S3ObjectClient{
		KS3:         ks3Client,
		bucketNames: bucketNames,
	}
	return &client, nil
}

//func buildSSEParsedConfig(cfg KS3Config) (*SSEParsedConfig, error) {
//	return nil, nil
//}

func buildKS3Config(cfg KS3Config) (*ks3aws.Config, []string, error) {
	// While extending S3 configuration this http config was copied in order to
	// to maintain backwards compatibility with previous versions of Cortex while providing
	// more flexible configuration of the http client
	// https://github.com/weaveworks/common/blob/4b1847531bc94f54ce5cf210a771b2a86cd34118/aws/config.go#L23
	transport := http.RoundTripper(&http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       cfg.HTTPConfig.IdleConnTimeout,
		MaxIdleConnsPerHost:   100,
		TLSHandshakeTimeout:   cfg.HTTPConfig.TLSHandshakeTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.HTTPConfig.ResponseHeaderTimeout),
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.HTTPConfig.InsecureSkipVerify},
	})

	if cfg.Inject != nil {
		transport = cfg.Inject(transport)
	}

	credentials := ks3credentials.NewStaticCredentials(cfg.AccessKeyID, cfg.SecretAccessKey, "")
	ks3Config := &ks3aws.Config{
		HTTPClient: &http.Client{
			Transport: transport,
		},
		Region:           cfg.Region,
		Credentials:      credentials,
		Endpoint:         cfg.Endpoint,         //ks3地址
		DisableSSL:       cfg.DisableSSL,       //是否禁用https
		LogLevel:         cfg.LogLevel,         //是否开启日志,0为关闭日志，1为开启日志
		S3ForcePathStyle: cfg.S3ForcePathStyle, //是否强制使用path style方式访问
		LogHTTPBody:      cfg.LogHTTPBody,      //是否把HTTP请求body打入日志
		Logger:           os.Stdout,            //打日志的位置
	}

	if cfg.AccessKeyID != "" && cfg.SecretAccessKey == "" ||
		cfg.AccessKeyID == "" && cfg.SecretAccessKey != "" {
		return nil, nil, errors.New("must supply both an Access Key ID and Secret Access Key or neither")
	}

	var bucketNames []string
	if cfg.BucketNames != "" {
		bucketNames = strings.Split(cfg.BucketNames, ",") // comma separated list of bucket names
	}

	if len(bucketNames) == 0 {
		return nil, nil, errors.New("at least one bucket name must be specified")
	}

	return ks3Config, bucketNames, nil
}

// Stop fulfills the chunk.ObjectClient interface
func (a *S3ObjectClient) Stop() {}

// DeleteObject deletes the specified objectKey from the appropriate S3 bucket
func (a *S3ObjectClient) DeleteObject(ctx context.Context, objectKey string) error {
	_, err := a.KS3.DeleteObject(&ks3.DeleteObjectInput{
		Bucket: aws.String(a.bucketFromKey(objectKey)),
		Key:    aws.String(objectKey),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == s3.ErrCodeNoSuchKey {
				return chunk.ErrStorageObjectNotFound
			}
		}
		return err
	}

	return nil
}

// bucketFromKey maps a key to a bucket name
func (a *S3ObjectClient) bucketFromKey(key string) string {
	if len(a.bucketNames) == 0 {
		return ""
	}

	hasher := fnv.New32a()
	hasher.Write([]byte(key)) //nolint: errcheck
	hash := hasher.Sum32()

	return a.bucketNames[hash%uint32(len(a.bucketNames))]
}

// GetObject returns a reader for the specified object key from the configured S3 bucket. If the
// key does not exist a generic chunk.ErrStorageObjectNotFound error is returned.
func (a *S3ObjectClient) GetObject(ctx context.Context, objectKey string) (io.ReadCloser, error) {
	var resp *ks3.GetObjectOutput

	// Map the key into a bucket
	bucket := a.bucketFromKey(objectKey)

	err := instrument.CollectedRequest(ctx, "KS3.GetObject", ks3RequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
		var err error
		//resp, err = a.S3.GetObjectWithContext(ctx, &s3.GetObjectInput{
		resp, err = a.KS3.GetObject(&ks3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(objectKey),
		})
		return err
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == s3.ErrCodeNoSuchKey {
				return nil, chunk.ErrStorageObjectNotFound
			}
		}
		return nil, err
	}

	return resp.Body, nil
}

// PutObject into the store
func (a *S3ObjectClient) PutObject(ctx context.Context, objectKey string, object io.ReadSeeker) error {
	return instrument.CollectedRequest(ctx, "KS3.PutObject", ks3RequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
		putObjectInput := &ks3.PutObjectInput{
			Body:   object,
			Bucket: aws.String(a.bucketFromKey(objectKey)),
			Key:    aws.String(objectKey),
		}

		//if a.sseConfig != nil {
		//	putObjectInput.ServerSideEncryption = aws.String(a.sseConfig.ServerSideEncryption)
		//	putObjectInput.SSEKMSKeyId = a.sseConfig.KMSKeyID
		//	putObjectInput.SSEKMSEncryptionContext = a.sseConfig.KMSEncryptionContext
		//}

		//_, err := a.S3.PutObjectWithContext(ctx, putObjectInput)
		_, err := a.KS3.PutObject(putObjectInput)
		return err
	})
}

// List implements chunk.ObjectClient.
func (a *S3ObjectClient) List(ctx context.Context, prefix, delimiter string) ([]chunk.StorageObject, []chunk.StorageCommonPrefix, error) {
	var storageObjects []chunk.StorageObject
	var commonPrefixes []chunk.StorageCommonPrefix

	for i := range a.bucketNames {
		err := instrument.CollectedRequest(ctx, "KS3.List", ks3RequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
			//input := s3.ListObjectsV2Input{
			input := ks3.ListObjectsInput{
				Bucket:    aws.String(a.bucketNames[i]),
				Prefix:    aws.String(prefix),
				Delimiter: aws.String(delimiter),
			}

			for {
				//output, err := a.S3.ListObjectsV2WithContext(ctx, &input)
				output, err := a.KS3.ListObjects(&input)
				if err != nil {
					return err
				}

				for _, content := range output.Contents {
					storageObjects = append(storageObjects, chunk.StorageObject{
						Key:        *content.Key,
						ModifiedAt: *content.LastModified,
					})
				}

				for _, commonPrefix := range output.CommonPrefixes {
					commonPrefixes = append(commonPrefixes, chunk.StorageCommonPrefix(aws.StringValue(commonPrefix.Prefix)))
				}

				if output.IsTruncated == nil || !*output.IsTruncated {
					// No more results to fetch
					break
				}

				//if output.NextContinuationToken == nil {
				if output.NextMarker == nil {
					// No way to continue
					break
				}
				//input.SetContinuationToken(*output.NextContinuationToken)
				input.Marker = output.NextMarker
			}

			return nil
		})

		if err != nil {
			return nil, nil, err
		}
	}

	return storageObjects, commonPrefixes, nil
}
