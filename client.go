package antchain

import (
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

type Config struct {
	BizID      string `json:"biz_id"`      // 链ID
	Endpoint   string `json:"endpoint"`    // 请求地址
	TenantID   string `json:"tenant_id"`   // 租户ID
	AccessID   string `json:"access_id"`   // 访问ID
	Account    string `json:"account"`     // 链账户
	MyKmsKeyID string `json:"mykmskey_id"` // 托管标识
}

// Client 发送请求使用的客户端
type Client interface {
	// CreateAccount 创建账户
	CreateAccount(ctx context.Context, account, kmsID string, gas int) (string, error)

	// Deposit 存证
	Deposit(ctx context.Context, content string, gas int) (string, error)

	// DeploySolidity 部署Solidity合约
	DeploySolidity(ctx context.Context, name, code string, gas int) (string, error)

	// AsyncCallSolidity 异步调用Solidity合约
	AsyncCallSolidity(ctx context.Context, contractName, methodSign, inputParams, outTypes string, gas int) (string, error)

	// QueryTransaction 查询交易
	QueryTransaction(ctx context.Context, hash string) (string, error)

	// QueryReceipt 查询交易回执
	QueryReceipt(ctx context.Context, hash string) (string, error)

	// QueryBlockHeader 查询块头
	QueryBlockHeader(ctx context.Context, blockNumber int64) (string, error)

	// QueryBlockBody 查询块体
	QueryBlockBody(ctx context.Context, blockNumber int64) (string, error)

	// QueryLastBlock 查询最新块高
	QueryLastBlock(ctx context.Context) (string, error)

	// QueryAccount 查询账户
	QueryAccount(ctx context.Context, account string) (string, error)

	// SetHTTPClient 设置自定义 http.Client
	SetHTTPClient(c *http.Client)
}

type ChainCallOption func(params X)

func WithParam(key string, value interface{}) ChainCallOption {
	return func(params X) {
		params[key] = value
	}
}

type client struct {
	hc  HTTPClient
	cfg *Config
	key *PrivateKey
}

func (c *client) shakehand(ctx context.Context) (string, error) {
	timeStr := strconv.FormatInt(time.Now().UnixMilli(), 10)

	sign, err := c.key.Sign(crypto.SHA256, []byte(c.cfg.AccessID+timeStr))

	if err != nil {
		return "", err
	}

	params := X{
		"accessId": c.cfg.AccessID,
		"time":     timeStr,
		"secret":   hex.EncodeToString(sign),
	}

	return c.do(ctx, c.cfg.Endpoint+SHAKE_HAND, params)
}

func (c *client) chainCall(ctx context.Context, method string, options ...ChainCallOption) (string, error) {
	token, err := c.shakehand(ctx)

	if err != nil {
		return "", err
	}

	params := make(X)

	for _, f := range options {
		f(params)
	}

	params["bizid"] = c.cfg.BizID
	params["accessId"] = c.cfg.AccessID
	params["method"] = method
	params["token"] = token

	return c.do(ctx, c.cfg.Endpoint+CHAIN_CALL, params)
}

func (c *client) chainCallForBiz(ctx context.Context, method string, options ...ChainCallOption) (string, error) {
	token, err := c.shakehand(ctx)

	if err != nil {
		return "", err
	}

	params := make(X)

	for _, f := range options {
		f(params)
	}

	params["orderId"] = uuid.New().String()
	params["bizid"] = c.cfg.BizID
	params["account"] = c.cfg.Account
	params["mykmsKeyId"] = c.cfg.MyKmsKeyID
	params["method"] = method
	params["accessId"] = c.cfg.AccessID
	params["tenantid"] = c.cfg.TenantID
	params["token"] = token

	return c.do(ctx, c.cfg.Endpoint+CHAIN_CALL_FOR_BIZ, params)
}

func (c *client) SetHTTPClient(cli *http.Client) {
	c.hc = NewHTTPClient(cli)
}

type LogData struct {
	URL        string        `json:"url"`
	Method     string        `json:"method"`
	Body       []byte        `json:"body"`
	StatusCode int           `json:"status_code"`
	Response   []byte        `json:"response"`
	Duration   time.Duration `json:"duration"`
	Error      error         `json:"error"`
}

func (c *client) do(ctx context.Context, reqURL string, params X) (string, error) {
	body, err := json.Marshal(params)

	if err != nil {
		return "", err
	}

	resp, err := c.hc.Do(ctx, http.MethodPost, reqURL, body, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	ret := gjson.ParseBytes(b)

	if !ret.Get("success").Bool() {
		return "", fmt.Errorf("Err %s | %s", ret.Get("code").String(), ret.Get("data").String())
	}

	return ret.Get("data").String(), nil
}

func NewClientWithAccessKeyBlock(keyBlock []byte, cfg *Config) (Client, error) {
	pk, err := NewPrivateKeyFromPemBlock(keyBlock)

	if err != nil {
		return nil, err
	}

	return &client{
		hc:  NewDefaultHTTPClient(),
		cfg: cfg,
		key: pk,
	}, nil
}

func NewClientWithAccessKeyFile(keyFile string, cfg *Config) (Client, error) {
	pk, err := NewPrivateKeyFromPemFile(keyFile)

	if err != nil {
		return nil, err
	}

	return &client{
		hc:  NewDefaultHTTPClient(),
		cfg: cfg,
		key: pk,
	}, nil
}
