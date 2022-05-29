/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/aoyouer/go-ngx-reqlimiter/internal"
	"github.com/spf13/cobra"
)

// startCmd represents the start command
var (
	rate           *float64
	burst          *int
	ip             *string
	port           *string
	onlyUnixSocket *bool
)
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Nginx request rate limiter",
	Long: `An nginx request rate limiter depends on ip.
Add 
	log_format limiter '$remote_addr $request';
	access_log syslog:server=unix:/var/run/go-ngx-limiter.sock limiter;
to your nginx config file to make it work.
All rules are appended to the NGX-REQLIMITER CHAIN in filter table, which will be cleared when exit.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		limiter := internal.NewReqLimiter(*ip+":"+*port, *onlyUnixSocket, *rate, *burst)
		limiter.Start()
	},
}

func init() {
	rootCmd.AddCommand(startCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rate = startCmd.Flags().Float64P("rate", "r", 50, "Rate limit")
	burst = startCmd.Flags().IntP("burst", "b", 100, "Rate burst")
	ip = startCmd.Flags().StringP("ip", "i", "127.0.0.1", "Bind ip")
	port = startCmd.Flags().StringP("port", "p", "514", "Bind port")
	onlyUnixSocket = startCmd.Flags().BoolP("unix-only", "u", false, "Using unix socket only")
}
