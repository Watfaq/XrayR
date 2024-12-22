package mylego

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var defaultPath string

func New(certConf *CertConfig) (*LegoCMD, error) {
	// Set default path to configPath/cert
	var p string
	configPath := os.Getenv("XRAY_LOCATION_CONFIG")
	if configPath != "" {
		p = configPath
	} else if cwd, err := os.Getwd(); err == nil {
		p = cwd
	} else {
		p = "."
	}

	defaultPath = filepath.Join(p, "cert")
	lego := &LegoCMD{
		C:    certConf,
		path: defaultPath,
	}

	return lego, nil
}

func (l *LegoCMD) getPath() string { //nolint:unused // leave it here
	return l.path
}

func (l *LegoCMD) getCertConfig() *CertConfig { //nolint:unused // leave it here
	return l.C
}

// DNSCert cert a domain using DNS API
func (l *LegoCMD) DNSCert() (certPath, keyPath string, err error) {
	defer func() (string, string, error) {
		// Handle any error
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			return "", "", err
		}
		return certPath, keyPath, nil
	}() //nolint:errcheck // leave it here

	// Set Env for DNS configuration
	for key, value := range l.C.DNSEnv {
		os.Setenv(strings.ToUpper(key), value)
	}

	// First check if the certificate exists
	certPath, keyPath, err = checkCertFile(l.C.CertDomain)
	if err == nil {
		return certPath, keyPath, nil
	}

	err = l.Run()
	if err != nil {
		return "", "", err
	}
	certPath, keyPath, err = checkCertFile(l.C.CertDomain)
	if err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// HTTPCert cert a domain using http methods
func (l *LegoCMD) HTTPCert() (certPath, keyPath string, err error) {
	defer func() (string, string, error) {
		// Handle any error
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			return "", "", err
		}
		return certPath, keyPath, nil
	}() //nolint:errcheck // leave it here

	// First check if the certificate exists
	certPath, keyPath, err = checkCertFile(l.C.CertDomain)
	if err == nil {
		return certPath, keyPath, nil
	}

	err = l.Run()
	if err != nil {
		return "", "", err
	}

	certPath, keyPath, err = checkCertFile(l.C.CertDomain)
	if err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}

// RenewCert renew a domain cert
func (l *LegoCMD) RenewCert() (certPath, keyPath string, ok bool, err error) {
	defer func() (string, string, bool, error) {
		// Handle any error
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			return "", "", false, err
		}
		return certPath, keyPath, ok, nil
	}() //nolint:errcheck // leave it here

	ok, err = l.Renew()
	if err != nil {
		return
	}

	certPath, keyPath, err = checkCertFile(l.C.CertDomain)
	if err != nil {
		return
	}

	return
}

func checkCertFile(domain string) (absCertPath, absKeyPath string, err error) {
	keyPath := path.Join(defaultPath, "certificates", fmt.Sprintf("%s.key", sanitizedDomain(domain)))
	certPath := path.Join(defaultPath, "certificates", fmt.Sprintf("%s.crt", sanitizedDomain(domain)))
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("cert key failed: %s", domain)
	}
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("cert cert failed: %s", domain)
	}
	absKeyPath, _ = filepath.Abs(keyPath)
	absCertPath, _ = filepath.Abs(certPath)
	return absCertPath, absKeyPath, nil
}
