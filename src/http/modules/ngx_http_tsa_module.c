

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> /* X509_PURPOSE */
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif /* OPENSSL_NO_ENGINE */

static ngx_int_t
ngx_http_tsa_handler(ngx_http_request_t* r);
static ngx_int_t
ngx_http_tsa_init(ngx_conf_t* cf);

// clang-format off

static ngx_http_module_t  ngx_http_tsa_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_tsa_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_tsa_module = {
    NGX_MODULE_V1,
    &ngx_http_tsa_module_ctx,              /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

// rootts.crt
static const char broottscrt[] = 
"-----BEGIN CERTIFICATE-----\n"
"MIIGIDCCBAigAwIBAgIUT/k9gDyp1WidP5w4nkyKn7KqJvQwDQYJKoZIhvcNAQEL\n"
"BQAwga8xCzAJBgNVBAYTAlVTMRMwEQYDVQQKDApDdXN0b20gSW5jMTAwLgYDVQQL\n"
"DCdodHRwczovL2dpdGh1Yi5jb20vMHg3Y2MvbmdpbngvdHJlZS90c2ExKjAoBgNV\n"
"BAMMIUN1c3RvbSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eTEtMCsGCSqGSIb3\n"
"DQEJARYeMHg3Y2NAdXNlcnMubm9yZXBseS5naXRodWIuY29tMCAXDTAwMDEwMTAw\n"
"MDAwMFoYDzIwOTkxMjMxMjM1OTU5WjCBpDELMAkGA1UEBhMCVVMxEzARBgNVBAoM\n"
"CkN1c3RvbSBJbmMxMDAuBgNVBAsMJ2h0dHBzOi8vZ2l0aHViLmNvbS8weDdjYy9u\n"
"Z2lueC90cmVlL3RzYTEfMB0GA1UEAwwWQ3VzdG9tIFRpbWVzdGFtcGluZyBDQTEt\n"
"MCsGCSqGSIb3DQEJARYeMHg3Y2NAdXNlcnMubm9yZXBseS5naXRodWIuY29tMIIC\n"
"IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5WpDCa109Ic+oDGj9F3ZdONI\n"
"CZuI8ctyNnJqkXDGEsuvY5g/URyfGXS6S/2knaWQa+Z7qaAY3IQeSj4NgZ6ZpxkH\n"
"6ugBkG7VO3Rh+FmCCEA5DsnmYUAO/lUeHV9bWoIm6uqa5ylHseBl5fI7y3NXGLR2\n"
"6BIi8u6UhMHAuSRzwH/nkatBz8vApivl9hmoSzfFX/3K2Pu5JOvQGYcCePS0oAbG\n"
"yz1u3jRkeNiSiYb7RvrGs8AoG9wzoG8kfGZ7wwAjd21pmhLhqJ8Wk97GBQx4BrAI\n"
"zHey+fqB219LX4KSmjL3iQMNFlQmCVeFZOIYSQGOZr/PF7WxhkcfskYdjB0WIjmH\n"
"COlE/AWkKpFBCzs5FHvFnnx8C0WCtK+PSTyBxAjCNogbzGjzCz/apHBdB0dwKA3v\n"
"D3/0ahIsXysn4G5/BkTpLjTvO4AMKgy9BONfHMfoFYWrpfCkRvKhp4fasj+C7QGH\n"
"dIIRXK8gnEzVeVVuWyFNG8kZ7OYQsYp2WENSSpMIQYoTmPfWbxqdR0BgOch+05mq\n"
"c+aq0qJ8ux9Q151su9N2vsGAvuqZUNfdPTFILpW/ublR/BNpIbjLPvxLqMmzQUzm\n"
"vw1qs/dFL5nQrnhcNsmGdMEIXeO8zby7yUpYRqZSCVjrDWTln4dXFhOZVmyN0YdS\n"
"ig2BW3qqhQvdqlWZOysCAwEAAaM7MDkwDgYDVR0PAQH/BAQDAgGGMBYGA1UdJQEB\n"
"/wQMMAoGCCsGAQUFBwMIMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQAD\n"
"ggIBAEhNnifoLVRwEDGAFdB5NwDHMAbghdcpX12Fa24hG9pK1kP6LxznqH4GzRNE\n"
"4zLQ/dQOpUw93xFX823KTM+jG7jH2MU/FaWkjYpJBPf1pq3E9BJ27JTnUjY28Top\n"
"hrTNWkq3GUPRbBCrTo8+5vXj/drF7XXVL3MnF9wEWMLaSM7pHTwQPt7fYieLfjzA\n"
"fM8+XzhQTis0/Dm3Tpv/VRf9n5txnQDYUId0viVX8OGiPHU0c24ET8nYWb8Ec4ZX\n"
"Ol5oIs+JQzbiCK9XUABIOZh+nvPMmdrbMjA+iTpTkudM2YzOC2jfhw/X08jGXlDM\n"
"GL+v60GSNtxVKX4NEd9dVC9trz5tZHmM157TzWk6VswFf5VYVBeZrmFQAAeM7pHe\n"
"gd3Nt36Slhn0dKfzTMNRqR+vBo88lb0ZCC6IBkQQuh6+HfY+4FKVfmlt6VSfSO/S\n"
"fI7vgJEaQr4DdEgzahiyGtL9wGk2JHZ2txntKRxKXbohgdLPftWVPJsXaTcA1tzl\n"
"7olcDmzZVlz9Fm+vhXd9GerWUFw1Nw7swazMirPgl6urhaPkIpb+zoAcdbZCPz+e\n"
"BUHBa3US4nLYPOp1i0ttDpc3SFncMHC9vFVAFxKavika9iskBxd09qiviHvNsc1m\n"
"jh+TpfgLQ88xuw18mUEkBEt8Kg6Znhc1eBQlj+NIHeExXDOF\n"
"-----END CERTIFICATE-----\n\n"
;

// ts.pem
static const char bts[] = 
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIJKAIBAAKCAgEAwIfvBrPPKe0niKOiGyB2bjUflwUsDaHP274dcRtal3/Rxl/F\n"
"UmDgwxj9pzcbXQWc3V2ylPiwloaCXiq/DY729xCQ3rFjNHMbo6q0sRcoTbFlqMKC\n"
"E7T/yXTzYSm+oOtCgIGPe6EDBwo3bsE3W+4/lSpcCANmihYjdzontIpB84+vat3m\n"
"X48rcn7x+CWgmTutrlFbnCUCT+J5G/g24P5Ml7vdyBfWEtAZCFEIK2wG/ZuxYA4x\n"
"mInAFwmRHP3tfxkSLSkFr8l1049rN6ru8HTHvHrD8usGb7Y1EkJOt1da3WA7hYg9\n"
"Shn0TTg/RcUXd/AbHurnMHj7Eqky37k52Y+6k+OVANeFn0252sD56pewUsQI/zvU\n"
"0it/h95zoqlD29bYaB7Ly3AI3jvj+GmIoXTsCeGodmvDr3yVKqRkkBa0NFJ5VWI1\n"
"7/Vb0ak+zEYsALKT9rjAT7pHef7nja3siovC667touMjwgo634FaCf/nfbu8WwgH\n"
"4mHkr/GVHIrVNY2xM9rUy7AX8s0hJIslhL4+j7XlLyvbYHW3EGycUISgWLpihVK5\n"
"r53/fQGGnwMf9zDKH13D6k2dE/mjXlbqcrYU96PGsmfowYMavvLVdPsuAIrmYcxP\n"
"Fl8YtPfEObCwYwKLivLHA8WsSsJEIsfD+GX2PkP+C8/i4a5Cj9H/qfviBDcCAwEA\n"
"AQKCAgAyerGKAVT8uihWZAjZse47QQRyVTHStS1JgRQ5FqHu/N1kdLHIwovLu16u\n"
"G/25qwIQ7EMpWfb60HOX+v8yr9xCtP421S2cj92cUOKlV9wCWtO7ppvyTM+P43D4\n"
"dbh8epJqHQ4grPudOemEyXYZTWMwWfXdR/73j4xm80F7zZAzKuYkT9/aCDCtCWmp\n"
"1TvBUWtdPAmX7AAqL8fvNGo3HZW5ZtFkaBOBxTv6+Tv6Ho3Kqqqb87y/MMbDg4ef\n"
"oVhGra0dWBccmuagvIaxBsk1FHlWCp4br9F1MsHBcs8utOGnD1cr0Ke5KQrrwCae\n"
"xWk80iBaP96zz9SMdP5YuDjZuRyCuwnzq4G8Db1itejEYszZKzQpIn3A8G3+2JFr\n"
"ZM1tQu3nI+FCPjbJaSpmclPgvwN5Cb8XALqpq0KTrA6YHJc0RH8FuZgo44of8s5N\n"
"5sZjfOrhulNtnq8zfEwFcnwrgiBY+lLA6F89dmATu2V6UNI9G4V3gSPZpAUiKJ5J\n"
"sC3F/eKEn+cL+oowTlfDbcF1PJWbzzbCEESmWd5EL73LfXWlwBwELHoGBysMryhR\n"
"MfO/rYkHResm1XWXLGT1ckTC5i9jPHN4CUMqbLyhfKMqhHDoMfY2Mdse/S5MVN7j\n"
"nH+i+q7h1e4JKe8wxKXMtTaVVeRrMXglGp40jo3p/9okF+DXiQKCAQEA86Qkgw+f\n"
"PVBMdwqaAt7X5UaEYVUysBbb/0mgmvCQY+hBP1oJRQ6PPnzdwBN6Ux/b4xW9Yu4x\n"
"yuTNcLPjf36UA45fEWVrilVjWQeX6gW4sdgY54uvXBZJx3l3yV/whFt3q3cYx/7G\n"
"IDHh0YZfGq92Ebjo2KKpcevaDYvxKVKz9g8cO62POwx+eHmN3F/wr5lJBjmv+ec0\n"
"//N0i8YtjlONLKaEBvkfn18soziPrlgF3pEBdpPxOUHdmwCQH4B341vZtUHkIQGf\n"
"UVwfO9Vilj4EICURDh5p4cbHqFoRgcem7wqF4UHzc+XZXSh5VdQ/RmAq00URYGmH\n"
"trCU9NE0F5oNvQKCAQEAykwWk3Xfah/NQpkA8NAM2Cee0tPWZR8sWPhHD+/kLrsF\n"
"4EIB0mfzqcAz38mUzRTtkf3JaRzZPwbdjrc2S1O1Uc3F14NZ25FaBc8dCu8MfnEB\n"
"zwsAQK5VL+JEdTBlMdJ3mBQ8cEWhBkZIFSXleLwqUkw5fM1s57Ts/K+j32FAFsTX\n"
"vuvxLnfjOg9Uc41aCsJpX1gL6RrKzlsgEnLVwSuJ5lqUdJX9dy7sj4O0NVD77LWg\n"
"QBhRY25RUjk8zeKcKMHixbsxVzqCi0TAUtQLbXua0bolnGVP82adAUyAewWGuFer\n"
"O82xORzq/5yDZOz9EW+2DvvVfacaGdwEV8dZZAV3AwKCAQAgiVsW5Y8ucPrFKvVG\n"
"TNwoEjK7jNUoDuVyQjLgfh/KN8n+29dBEaCvh51VeURstWR3/v87pvOfVM7aritD\n"
"a3P4xZqMiC7EWoLZ8NmotvrjRSiOQ2k3swJHUUFd8yH7ivuAOndkvfFXe1Hc2UT6\n"
"G1R5KWhvBcn7HLQR+w5JpnHB+mKa1aK7EAATtqfrNiS+Tooh+rI1fVrmk2yM/fo3\n"
"d5Dy1YnsJHjEn8EmSvdlIPwnrNW1MCyWqOUfPgQBMPbRtgJs4k/E2KKeCt9g7i4s\n"
"QjvqzwhoCke5jwI6yUxtOGxin9UhL92DLL7KYg1SGPYaP914OVEIvw8QpqQ9zXJX\n"
"dItBAoIBAG0SHy38ZKvsX5gjtI0iL3qvygMz8iltaFTD8FSYa/gCIEXscN0H7Sk+\n"
"Fvn2zsLQINMQ+XIx+rPvuK9E+wIcLOvhPWVYTa+Dq/zr0WXew2a8+VOvQ8Cb/hQm\n"
"M/DXWghFyPN3HasO76XZaO32E8ZH9a2PqYMvoyM+unP3IyzCW3KrSQOIZO4/94SL\n"
"VWZD9SNN9NBSQYG6T1R5b05jGfrfxacseVRutk13QFaUlSoV8u6Kcs98DQ3GIhRq\n"
"Be2f28Bh4SnpJs44HsCGHgfKiirKdQvVCIhNW5EJZ2eW3sL1lNB5fDpvSblYbR/K\n"
"PFHDMSMgjxF/GHl6CimdJb5KHlk+VQ8CggEBAJLkWYIoM/V3wzCmdeLEa6ueYDGu\n"
"AseugYECZ8i014eJ+f3qNPYU/So4yoRgPoaHu+5GVY3r1jBGjhY0qu7vbsrg+Qde\n"
"NHmdb7D7sBer2T4sWAL+jR42FijgjP/T7qzzE+Qrc+yQrqr24hR9uZe5tZUdD+4p\n"
"kV45TOmqeQDd1AHKErrWNZrDmIphPpWJZQBzJM2DDlYACoMXDYp9nj1VFkq4sHfa\n"
"YKXCuUPibD+eEjzQrzDV/g/+hFXdLuhX/1GRMYi2uPnv5mU323hsIdldMfnbTC8n\n"
"tUcRllhT/+1VUJvRLN9O+/j96PQeUx0W2LYfcpIYjrYaVvHsgAxorCek2cU=\n"
"-----END RSA PRIVATE KEY-----\n\n"
;

// ts.crt
static const char btscrt[]=
"-----BEGIN CERTIFICATE-----\n"
"MIIGFzCCA/+gAwIBAgIUKgC3qzEe92Tx9YJoTRi79fTdt8IwDQYJKoZIhvcNAQEL\n"
"BQAwgaQxCzAJBgNVBAYTAlVTMRMwEQYDVQQKDApDdXN0b20gSW5jMTAwLgYDVQQL\n"
"DCdodHRwczovL2dpdGh1Yi5jb20vMHg3Y2MvbmdpbngvdHJlZS90c2ExHzAdBgNV\n"
"BAMMFkN1c3RvbSBUaW1lc3RhbXBpbmcgQ0ExLTArBgkqhkiG9w0BCQEWHjB4N2Nj\n"
"QHVzZXJzLm5vcmVwbHkuZ2l0aHViLmNvbTAgFw0wMDAxMDEwMDAwMDBaGA8yMDk5\n"
"MTIzMTIzNTk1OVowgakxCzAJBgNVBAYTAlVTMRMwEQYDVQQKDApDdXN0b20gSW5j\n"
"MTAwLgYDVQQLDCdodHRwczovL2dpdGh1Yi5jb20vMHg3Y2MvbmdpbngvdHJlZS90\n"
"c2ExJDAiBgNVBAMMG0N1c3RvbSBUaW1lc3RhbXBpbmcgU2VydmljZTEtMCsGCSqG\n"
"SIb3DQEJARYeMHg3Y2NAdXNlcnMubm9yZXBseS5naXRodWIuY29tMIICIjANBgkq\n"
"hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwIfvBrPPKe0niKOiGyB2bjUflwUsDaHP\n"
"274dcRtal3/Rxl/FUmDgwxj9pzcbXQWc3V2ylPiwloaCXiq/DY729xCQ3rFjNHMb\n"
"o6q0sRcoTbFlqMKCE7T/yXTzYSm+oOtCgIGPe6EDBwo3bsE3W+4/lSpcCANmihYj\n"
"dzontIpB84+vat3mX48rcn7x+CWgmTutrlFbnCUCT+J5G/g24P5Ml7vdyBfWEtAZ\n"
"CFEIK2wG/ZuxYA4xmInAFwmRHP3tfxkSLSkFr8l1049rN6ru8HTHvHrD8usGb7Y1\n"
"EkJOt1da3WA7hYg9Shn0TTg/RcUXd/AbHurnMHj7Eqky37k52Y+6k+OVANeFn025\n"
"2sD56pewUsQI/zvU0it/h95zoqlD29bYaB7Ly3AI3jvj+GmIoXTsCeGodmvDr3yV\n"
"KqRkkBa0NFJ5VWI17/Vb0ak+zEYsALKT9rjAT7pHef7nja3siovC667touMjwgo6\n"
"34FaCf/nfbu8WwgH4mHkr/GVHIrVNY2xM9rUy7AX8s0hJIslhL4+j7XlLyvbYHW3\n"
"EGycUISgWLpihVK5r53/fQGGnwMf9zDKH13D6k2dE/mjXlbqcrYU96PGsmfowYMa\n"
"vvLVdPsuAIrmYcxPFl8YtPfEObCwYwKLivLHA8WsSsJEIsfD+GX2PkP+C8/i4a5C\n"
"j9H/qfviBDcCAwEAAaM4MDYwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoG\n"
"CCsGAQUFBwMIMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBABvLkbuj\n"
"qQlKCX5oVffAYaaB2EqNVeBdLFRDk2MNtSjJJ2+5pArCKIp8cHQcwmjNkHyJphXK\n"
"saU/xwOKSg6qne8XjeMWrCCsiema7b81IJWxijFl/CCTkllGZvysHxI+xQZMQ+cU\n"
"ySPbH2HHMZMVPy10EZ5G1kp6y6ZePtJAv3MxOWw8chAzXaS/5aMMmv4K27Lng7GA\n"
"Pox1KXSvHdPQi8WuyDBAtNd5hIxumcfRFVYVV//1fbjkwVa9TFuiB8iVA+tZ3rKZ\n"
"ZKLNmlMUQiBMdV9ybU4EYs6E65ihTs48YhqcEKuwgZWe3aoOwNWv9/Cvpr5fMvZJ\n"
"JT+aVJVAR2a+5qbmiT/MCfEtFa+siQFr1zySR8X7RwIb6vLSgQGys611FttvJkJ9\n"
"ltSBiTkDawvNYf/UN80qSdkVu5wtJgBqOzQ6KMHZhR3CC4h/icsB8bWMyz2Nwbs9\n"
"nSOE1YVZpJv/mKQhclMLWnAFmRm5+5rUgH/H5/4Y3lAg5ItF8++9b0yYEdI0kbxK\n"
"5UFdL5uYxTHOW2oKOZYVNNVgh3tV79Aysvsqp6DE1spCBjww/Qoh1bKEgEUTfLih\n"
"me9GPf05mBmeMlWtVGN7r7KvDeLsph5lrOrJINi7lsOpuq8HQyMch5TXENihOhre\n"
"cVpmft6FcqefefMdOfPGNQiXFcd3CWbW/LnD\n"
"-----END CERTIFICATE-----\n\n"
;

// clang-format on

static int
time_cb(struct TS_resp_ctx* ctx, void* data, long* sec, long* usec)
{
    *sec = *(int64_t*)data;
    *usec = 0;
    return 1;
}

static ASN1_INTEGER*
serial_cb(TS_RESP_CTX* ctx, void* data)
{
    return (ASN1_INTEGER*)data;
}

static ngx_int_t
output_usage(ngx_http_request_t* r)
{
    ngx_int_t rc;
    ngx_buf_t* b;
    ngx_chain_t out;

    r->headers_out.status = NGX_HTTP_OK;

    ngx_str_set(&r->headers_out.content_type, "text/plain");
    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_etag(r);

    b = ngx_create_temp_buf(r->pool, 1024);
    b->last = ngx_cpymem(b->last, "signtool.exe /tr ", 17);
    b->last = ngx_cpymem(b->last, "http://", 7);
    b->last = ngx_cpymem(b->last, r->headers_in.host->value.data, r->headers_in.host->value.len);
    b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);
    b->last = ngx_cpymem(b->last, " /td <sha1|sha256>", 18);
    b->last = ngx_cpymem(b->last, " <...>", 6);
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
    if (rc != NGX_OK) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_tsa_get_handler(ngx_http_request_t* r)
{
    output_usage(r);
    return NGX_OK;
}

static void
ngx_http_tsa_post_handler(ngx_http_request_t* r)
{
    int64_t ts;
    ngx_buf_t* buf;
    ngx_chain_t out;
    ngx_int_t rc;
    BIO* reply = NULL;
    ASN1_INTEGER* serial = NULL;
    TS_REQ* req = NULL;
    TS_RESP* resp = NULL;
    TS_RESP_CTX* resp_ctx = NULL;

    if (r->request_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PUT request body is unavailable");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    // not supported currently
    if (r->request_body->temp_file) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PUT request body is unavailable");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->request_body->bufs == NULL || r->request_body->bufs->next) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PUT request body is unavailable");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    do {
        BIGNUM* bn = NULL;
        BIO* b = NULL;
        const EVP_MD* md = NULL;
        STACK_OF(X509_INFO)* allcerts = NULL;
        X509* cert_obj = NULL;
        STACK_OF(X509)* othercerts = NULL;
        ASN1_OBJECT* policy_obj = NULL;

        resp_ctx = TS_RESP_CTX_new();

        if ((ts = ngx_atoi64(r->uri.data + 1, r->uri.len - 1)) == NGX_ERROR) {
            break;
        }

        b = BIO_new_mem_buf(r->request_body->bufs->buf->pos,
                            r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);
        req = d2i_TS_REQ_bio(b, NULL);
        BIO_free(b);
        b = NULL;

        if (req == NULL)
            break;

        if (TS_REQ_get_msg_imprint(req) == NULL)
            break;

        if (TS_MSG_IMPRINT_get_algo(TS_REQ_get_msg_imprint(req)) == NULL)
            break;

        md = EVP_get_digestbyobj(TS_MSG_IMPRINT_get_algo(TS_REQ_get_msg_imprint(req))->algorithm);

        TS_REQ_free(req);
        req = NULL;

        if (md == NULL)
            break;

        // CERTIFICATE
        b = BIO_new_mem_buf(btscrt, sizeof(btscrt));
        cert_obj = PEM_read_bio_X509_AUX(b, NULL, NULL, NULL);
        BIO_free(b);
        b = NULL;

        serial = ASN1_INTEGER_dup(X509_get_serialNumber(cert_obj));
        bn = ASN1_INTEGER_to_BN(serial, NULL);
        TS_RESP_CTX_set_signer_cert(resp_ctx, cert_obj);
        TS_RESP_CTX_set_signer_digest(resp_ctx, md);

        X509_free(cert_obj);
        cert_obj = NULL;

        ASN1_INTEGER_free(serial);
        serial = NULL;

        if (bn == NULL)
            break;

        BN_add_word(bn, 1);

        TS_RESP_CTX_set_serial_cb(resp_ctx, serial_cb, BN_to_ASN1_INTEGER(bn, NULL));

        BN_free(bn);
        bn = NULL;

        // PRIVATE KEY
        b = BIO_new_mem_buf(bts, sizeof(bts));
        TS_RESP_CTX_set_signer_key(resp_ctx, PEM_read_bio_PrivateKey(b, NULL, NULL, NULL));
        BIO_free(b);
        b = NULL;

        // INTERMEDIATE CERTIFICATE
        othercerts = sk_X509_new_null();

        b = BIO_new_mem_buf(broottscrt, sizeof(broottscrt));
        allcerts = PEM_X509_INFO_read_bio(b, NULL, NULL, NULL);
        BIO_free(b);
        b = NULL;

        for (int i = 0; i < sk_X509_INFO_num(allcerts); i++) {
            X509_INFO* xi = sk_X509_INFO_value(allcerts, i);
            if (xi->x509) {
                sk_X509_push(othercerts, xi->x509);
                xi->x509 = NULL;
            }
        }

        sk_X509_INFO_pop_free(allcerts, X509_INFO_free);
        TS_RESP_CTX_set_certs(resp_ctx, othercerts);
        sk_X509_free(othercerts);

        // WHAT?
        policy_obj = OBJ_txt2obj("1.2.3.4", 0);
        TS_RESP_CTX_set_def_policy(resp_ctx, policy_obj);
        ASN1_OBJECT_free(policy_obj);

        /////////////////////
        TS_RESP_CTX_set_time_cb(resp_ctx, time_cb, &ts);

        TS_RESP_CTX_add_md(resp_ctx, EVP_md5());
        TS_RESP_CTX_add_md(resp_ctx, EVP_sha1());
        TS_RESP_CTX_add_md(resp_ctx, EVP_sha256());
        TS_RESP_CTX_add_md(resp_ctx, EVP_sha384());
        TS_RESP_CTX_add_md(resp_ctx, EVP_sha512());

        TS_RESP_CTX_set_ess_cert_id_digest(resp_ctx, md);
        // TS_RESP_CTX_set_accuracy(resp_ctx, 1, 500, 100);
        TS_RESP_CTX_set_clock_precision_digits(resp_ctx, 0);
        // TS_RESP_CTX_add_flags(resp_ctx, TS_ORDERING);
        // TS_RESP_CTX_add_flags(resp_ctx, TS_TSA_NAME);
        b = BIO_new_mem_buf(r->request_body->bufs->buf->pos,
                            r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);

        resp = TS_RESP_create_response(resp_ctx, b);

        BIO_free(b);
        b = NULL;

        if (resp == NULL)
            break;

        reply = BIO_new(BIO_s_mem());
        i2d_TS_RESP_bio(reply, resp);
    } while (0);

    if (reply && BIO_number_written(reply)) {
        buf = ngx_create_temp_buf(r->pool, (size_t)BIO_number_written(reply));
        BIO_read(reply, buf->last, (size_t)BIO_number_written(reply));
        buf->last += (size_t)BIO_number_written(reply);

        buf->last_buf = (r == r->main) ? 1 : 0;
        buf->last_in_chain = 1;

        out.buf = buf;
        out.next = NULL;

        // r->headers_out.date = ngx_http_time();
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = buf->last - buf->pos;
        ngx_str_set(&r->headers_out.content_type, "application/timestamp-reply");

        rc = ngx_http_send_header(r);
        if (rc == NGX_OK)
            rc = ngx_http_output_filter(r, &out);
        ngx_http_finalize_request(r, rc);
    } else {
        ngx_http_finalize_request(r, output_usage(r));
    }

    if (reply)
        BIO_free(reply);
    if (serial)
        ASN1_INTEGER_free(serial);
    if (req)
        TS_REQ_free(req);
    if (resp)
        TS_RESP_free(resp);
    if (resp_ctx)
        TS_RESP_CTX_free(resp_ctx);
}

static ngx_int_t
ngx_http_tsa_handler(ngx_http_request_t* r)
{
    int64_t tgttime;

    if (r->uri.len < 2) {
        return NGX_DECLINED;
    }

    tgttime = ngx_atoi64(r->uri.data + 1, r->uri.len - 1);
    if (tgttime == NGX_ERROR) {
        return NGX_DECLINED;
    }

    switch (r->method) {
    case NGX_HTTP_GET:
        return ngx_http_tsa_get_handler(r);
    case NGX_HTTP_POST:
        r->request_body_in_single_buf = 1;
        return ngx_http_read_client_request_body(r, ngx_http_tsa_post_handler);
    }
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_tsa_init(ngx_conf_t* cf)
{
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_tsa_handler;

    return NGX_OK;
}
