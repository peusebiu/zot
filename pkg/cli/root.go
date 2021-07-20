package cli

import (
	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/api/config"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/mitchellh/mapstructure"
	dspec "github.com/opencontainers/distribution-spec"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// metadataConfig reports metadata after parsing, which we use to track
// errors.
func metadataConfig(md *mapstructure.Metadata) viper.DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.Metadata = md
	}
}

func NewRootCmd() *cobra.Command {
	showVersion := false
	conf := config.New()

	// "serve"
	serveCmd := &cobra.Command{
		Use:     "serve <config>",
		Aliases: []string{"serve"},
		Short:   "`serve` stores and distributes OCI images",
		Long:    "`serve` stores and distributes OCI images",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				viper.SetConfigFile(args[0])
				if err := viper.ReadInConfig(); err != nil {
					panic(err)
				}

				md := &mapstructure.Metadata{}
				if err := viper.Unmarshal(&conf, metadataConfig(md)); err != nil {
					panic(err)
				}

				// if haven't found a single key or there were unused keys, report it as
				// a error
				if len(md.Keys) == 0 || len(md.Unused) > 0 {
					panic(errors.ErrBadConfig)
				}
			}
			c := api.NewController(conf)
			if err := c.Run(); err != nil {
				panic(err)
			}
		},
	}

	// "garbage-collect"
	gcDelUntagged := false
	gcDryRun := false

	gcCmd := &cobra.Command{
		Use:     "garbage-collect <config>",
		Aliases: []string{"gc"},
		Short:   "`garbage-collect` deletes layers not referenced by any manifests",
		Long:    "`garbage-collect` deletes layers not referenced by any manifests",
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Interface("values", conf).Msg("configuration settings")
			if conf.Storage.RootDirectory != "" {
				if err := storage.Scrub(conf.Storage.RootDirectory, gcDryRun); err != nil {
					panic(err)
				}
			}
		},
	}

	gcCmd.Flags().StringVarP(&conf.Storage.RootDirectory, "storage-root-dir", "r", "",
		"Use specified directory for filestore backing image data")

	_ = gcCmd.MarkFlagRequired("storage-root-dir")
	gcCmd.Flags().BoolVarP(&gcDelUntagged, "delete-untagged", "m", false,
		"delete manifests that are not currently referenced via tag")
	gcCmd.Flags().BoolVarP(&gcDryRun, "dry-run", "d", false,
		"do everything except remove the blobs")

	rootCmd := &cobra.Command{
		Use:   "zot",
		Short: "`zot`",
		Long:  "`zot`",
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				log.Info().Str("distribution-spec", dspec.Version).Str("commit", config.Commit).
					Str("binary-type", config.BinaryType).Msg("version")
			}
			_ = cmd.Usage()
		},
	}

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(gcCmd)

	enableCli(rootCmd)

	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")

	return rootCmd
}
