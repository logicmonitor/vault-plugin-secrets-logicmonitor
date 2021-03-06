package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical/plugin"
	"github.com/logicmonitor/vault-plugin-secrets-logicmonitor/plugin"
)

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	err := flags.Parse(os.Args[1:])
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	err = plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: lmsecrets.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
