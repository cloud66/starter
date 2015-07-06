package packs

import (
	"fmt"
	"path/filepath"

	"github.com/cloud66/starter/common"
)

type Ruby struct {
	WorkDir     string
	Environment string

	Gemfile  string
	Version  string
	Packages *common.Lister
}

func (r *Ruby) Name() string {
	return "ruby"
}

func (r *Ruby) PackVersion() string {
	return "0.1"
}

func (r *Ruby) Detect() (bool, error) {
	r.Gemfile = filepath.Join(r.WorkDir, "Gemfile")

	// TODO: fetch git url and branch from the director
	return common.FileExists(r.Gemfile), nil
}

func (r *Ruby) OutputFolder() string {
	return r.WorkDir
}

func (r *Ruby) DefaultVersion() string {
	return "onbuild"
}

func (r *Ruby) Compile() (*common.ParseContext, error) {
	// we have a ruby app

	messages := common.NewLister()

	foundRuby, rubyVersion := common.GetRubyVersion(r.Gemfile)
	if foundRuby {
		r.Version = fmt.Sprintf("%s-onbuild", rubyVersion)
	} else {
		rubyVersion = common.AskUser("Can't find Ruby version from Gemfile:", "default")
		if rubyVersion == "default" {
			r.Version = r.DefaultVersion()
		} else {
			r.Version = fmt.Sprintf("%s-onbuild", rubyVersion)
		}
	}

	service := &common.Service{Name: "web"}

	isRails, _ := common.GetGemVersion(r.Gemfile, "rails")

	// port depends on the application server. for now we are going to fix to 3000
	if runsUnicorn, _ := common.GetGemVersion(r.Gemfile, "unicorn", "thin"); runsUnicorn {
		fmt.Println(common.MsgL2, "----> Found non Webrick application server", common.MsgReset)
		// The command here will be found in the Procfile
		service.Ports = []string{"9292:80:443"}
	} else {
		if isRails {
			service.Command = "bundle exec rails s _env:RAILS_ENV"
			service.Ports = []string{"3000:80:443"}
		} else {
			service.Command = "bundle exec rackup s _env:RACK_ENV"
			service.Ports = []string{"9292:80:443"}
		}
	}

	// add packages based on any other findings in the Gemfile
	r.Packages = common.NewLister()
	if hasRmagick, _ := common.GetGemVersion(r.Gemfile, "rmagick"); hasRmagick {
		fmt.Println(common.MsgL2, "----> Found Image Magick", common.MsgReset)
		r.Packages.Add("imagemagick", "libmagickwand-dev")
	}

	if hasSqlite, _ := common.GetGemVersion(r.Gemfile, "sqlite"); hasSqlite {
		fmt.Println(common.MsgL2, "----> Found sqlite", common.MsgReset)
		r.Packages.Add("libsqlite3-dev")
	}

	// look for DB
	dbs := common.NewLister()
	if hasMysql, _ := common.GetGemVersion(r.Gemfile, "mysql2"); hasMysql {
		fmt.Println(common.MsgL2, "----> Found Mysql", common.MsgReset)
		dbs.Add("mysql")
	}

	if hasPg, _ := common.GetGemVersion(r.Gemfile, "pg"); hasPg {
		fmt.Println(common.MsgL2, "----> Found PostgreSQL", common.MsgReset)
		dbs.Add("postgresql")
	}

	if hasRedis, _ := common.GetGemVersion(r.Gemfile, "redis"); hasRedis {
		fmt.Println(common.MsgL2, "----> Found Redis", common.MsgReset)
		dbs.Add("redis")
	}

	if hasMongoDB, _ := common.GetGemVersion(r.Gemfile, "mongo", "mongo_mapper", "dm-mongo-adapter", "mongoid"); hasMongoDB {
		fmt.Println(common.MsgL2, "----> Found MongoDB", common.MsgReset)
		dbs.Add("mongodb")
	}

	if hasElasticsearch, _ := common.GetGemVersion(r.Gemfile, "elasticsearch", "tire", "flex", "chewy"); hasElasticsearch {
		fmt.Println(common.MsgL2, "----> Found Elasticsearch", common.MsgReset)
		dbs.Add("elasticsearch")
	}

	if hasDatabaseYaml := common.FileExists("config/database.yml"); hasDatabaseYaml {
		fmt.Println(common.MsgL2, "----> Found config/database.yml", common.MsgReset)
		messages.Add(
			fmt.Sprintf("%s %s-> %s", 
				"database.yml: Make sure you are using environment variables.", 
				common.MsgReset, "http://help.cloud66.com/deployment/environment-variables"))
	}

	if hasMongoIdYaml := common.FileExists("config/mongoid.yml"); hasMongoIdYaml {
		fmt.Println(common.MsgL2, "----> Found config/mongoid.yml", common.MsgReset)
		messages.Add(
			fmt.Sprintf("%s %s-> %s", 
				"mongoid.yml: Make sure you are using environment variables.", 
				common.MsgReset, "http://help.cloud66.com/deployment/environment-variables"))
	}

	parseContext := &common.ParseContext{
		Services: []*common.Service{service},
		Dbs:      dbs.Items,
		EnvVars:  []*common.EnvVar{
			&common.EnvVar{Key: "RAILS_ENV", Value: r.Environment},
			&common.EnvVar{Key: "RACK_ENV", Value: r.Environment}},
		Messages: messages.Items}

	service.EnvVars = parseContext.EnvVars

	return parseContext, nil
}
