// Copyright © 2018 Lachlan Pease <predatory.kangaroo@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"crypto/tls"
	"fmt"
	"github.com/dyson/certman"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/predakanga/dumb-proxy/proxy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile              string
	egressIp             string
	verbosity            int
	proxyModeString      string
	disableConnect       bool
	omitForwarded        bool
	filteredDestinations []string
	listenAddr           string
	metricsAddr          string
	tlsCertificate       string
	tlsKey               string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "dumb-proxy",
	Short: "Very simple HTTP/HTTPS proxy, for use with nginx",
	Long: `Very simple HTTP/HTTPS proxy, for use with nginx.
Does not behave as a standard web proxy - do not use it with your web browser!`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: run,
	Args: cobra.NoArgs,
}

var proxyModeMap = map[string]proxy.ProxyMode {
	"http": proxy.HttpProxy,
	"transparent": proxy.TransparentProxy,
	"both": proxy.HttpAndTransparentProxy,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.dumb-proxy.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().CountVarP(&verbosity, "verbose", "v", "verbosity (use multiple times to increase)")

	// Server options
	rootCmd.Flags().StringVarP(&listenAddr, "listen", "l", ":43443", "address to listen on")
	rootCmd.Flags().StringVar(&metricsAddr, "metrics-listen", ":43440", "address to serve metrics on")
	rootCmd.Flags().StringVar(&tlsCertificate, "tls-certificate", "", "path to TLS certificate")
	rootCmd.Flags().StringVar(&tlsKey, "tls-key", "", "path to TLS key")
	// Proxy options
	rootCmd.Flags().StringVarP(&egressIp, "egress-ip", "e", "", "address to make requests from")
	// Disable connect
	rootCmd.Flags().BoolVar(&disableConnect, "disable-connect", false, "disables forwarding CONNECT requests")
	// Proxy mode
	rootCmd.Flags().StringVarP(&proxyModeString, "mode", "m", "both", "requests to handle: http, transport, or both")
	// Omit forwarded
	rootCmd.Flags().BoolVar(&omitForwarded, "omit-forwarded", false, "omits the X-Forwarded-For header from requests")
	// Filters
	rootCmd.Flags().StringArrayVarP(&filteredDestinations, "exclude", "x", []string {}, "rejects any requests to a destination (domain name, IP or CIDR)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".dumb-proxy" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".dumb-proxy")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

// Argument may be either an IP address or a hostname
type MatcherFunc func(string) bool

func parseExclusions(exclusions []string) []MatcherFunc {
	matchers := make([]MatcherFunc, len(exclusions))

	for _, exclusion := range exclusions {
		// Try parsing as an IP first

		if ip := net.ParseIP(exclusion); ip != nil {
			ipMatcher := func(target string) bool {
				// ResolveIP is a no-op if target is already an IP
				if targetAddr, err := net.ResolveIPAddr("tcp", target); err != nil {
					// Fail open, or closed? Closed would cause 404 when it should return 500
					log.Warnf("Failed to resolve %v in matcher: %v", target, err)
					return true
				} else {
					if targetAddr.IP.Equal(ip) {
						return false
					}
				}
				return true
			}
			matchers = append(matchers, ipMatcher)
		} else if _, network, err := net.ParseCIDR(exclusion); err != nil {
			netMatcher := func(target string) bool {
				if targetAddr, err := net.ResolveIPAddr("tcp", target); err != nil {
					log.Warnf("Failed to resolve %v in matcher: %v", target, err)
					return true
				} else {
					if network.Contains(targetAddr.IP) {
						return false
					}
				}
				return true
			}
			matchers = append(matchers, netMatcher)
		} else {
			// TODO: How do we validate the input domains? Do we want to lazily resolve them?
			// Just taking it at face value for now
			domainMatcher := func(target string) bool {
				return strings.EqualFold(exclusion, target)
			}
			matchers = append(matchers, domainMatcher)
		}
	}

	return matchers
}

func run(cmd *cobra.Command, args []string) {
	var localAddr net.Addr

	switch verbosity {
	case 0:
		log.SetLevel(log.WarnLevel)
	case 1:
		log.SetLevel(log.InfoLevel)
	case 2:
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.DebugLevel)
	}

	if egressIp != "" {
		log.Infof("Sending requests from %v", egressIp)
		// Log: Using IP localIP
		localAddr = &net.TCPAddr{
			IP: net.ParseIP(egressIp),
		}
	}

	matchers := parseExclusions(filteredDestinations)

	proxyMode, ok := proxyModeMap[proxyModeString]
	if !ok {
		log.Fatalf("Invalid proxy mode: %v", proxyModeString)
	}

	requestProxy := &proxy.Proxy{
		EgressAddress: localAddr,
		OmitForwardedHeaders: omitForwarded,
		DisableConnect: disableConnect,
		ProxyMode: proxyMode,
	}

	if len(matchers) > 0 {
		requestProxy.RequestFilter = func(request http.Request) bool {
			// Resolve the IP, then check it against each matcher,
			for _, matcher := range matchers {
				if !matcher(request.Host) {
					return false
				}
			}
			return true
		}
		requestProxy.TunnelFilter = func(destination string) bool {
			// Tunnel requests should always have a port
			if host, _, err := net.SplitHostPort(destination); err == nil {
				// We should never reach here; the address is vetted by proxy
				for _, matcher := range matchers {
					if !matcher(host) {
						return false
					}
				}
			}

			return true
		}
	}

	// FIXME: This is a really dodgy way of forcing output
	oldLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	log.Infof("Starting server on %v", listenAddr)
	log.SetLevel(oldLevel)


	go func() {
		// N.B. This isn't scoped to the metrics server because of the goroutine.
		// It happens because we override the handler for our proxy server
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(metricsAddr, nil); err != nil {
			log.Fatalf("Couldn't start metrics server: %v", err)
		}
	}()

	if tlsCertificate != "" {
		if certs, err := certman.New(tlsCertificate, tlsKey); err != nil {
			log.Fatalf("Failed to load TLS certificates: %v", err)
		} else {
			certLogger := proxy.LeveledLogger{
				Logger: log.StandardLogger(),
				Level: log.DebugLevel,
			}
			certs.Logger(certLogger)
			if err := certs.Watch(); err != nil {
				log.Fatalf("Couldn't watch TLS certificates: %v", err)
			}
			tlsServer := &http.Server{
				Addr: listenAddr,
				Handler: requestProxy,
				TLSConfig: &tls.Config {
					GetCertificate: certs.GetCertificate,
				},
			}
			if err := tlsServer.ListenAndServeTLS("", ""); err != nil {
				log.Fatalf("Couldn't start server: %v", err)
			}
		}
	} else {
		if err := http.ListenAndServe(listenAddr, requestProxy); err != nil {
			log.Fatalf("Couldn't start server: %v", err)
		}
	}
}