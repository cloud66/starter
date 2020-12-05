package ruby

import (
	"fmt"
	"path/filepath"

	"github.com/cloud66-oss/starter/common"
	"github.com/cloud66-oss/starter/packs"
	"github.com/cloud66-oss/starter/packs/ruby/webservers"
)

type Analyzer struct {
	packs.AnalyzerBase
	Gemfile string
}

func (a *Analyzer) Analyze() (*Analysis, error) {
	a.Gemfile = filepath.Join(a.RootDir, "Gemfile")
	gitURL, gitBranch, buildRoot, err := a.ProjectMetadata()

	if err != nil {
		return nil, err
	}

	version := a.FindVersion()
	dbs := a.ConfirmDatabases(a.FindDatabases())
	envVars := a.EnvVars()
	packages := a.GuessPackages()
	framework := a.GuessFramework()
	a.CheckNotSupportedPackages(packages)

	services, err := a.AnalyzeServices(a, envVars, gitBranch, gitURL, buildRoot)

	// inject all the services with the databases used in the infrastructure
	for _, service := range services {
		service.Databases = dbs
	}

	if err != nil {
		return nil, err
	}

	analysis := &Analysis{
		AnalysisBase: packs.AnalysisBase{
			PackName:  a.GetPack().Name(),
			GitBranch: gitBranch,
			GitURL:    gitURL,
			Framework: framework,
			Messages:  a.Messages},
		DockerComposeYAMLContext: &DockerComposeYAMLContext{packs.DockerComposeYAMLContextBase{Services: services, Dbs: dbs}},
		ServiceYAMLContext:       &ServiceYAMLContext{packs.ServiceYAMLContextBase{Services: services, Dbs: dbs}},
		DockerfileContext:        &DockerfileContext{packs.DockerfileContextBase{Version: version, Packages: packages}}}
	return analysis, nil
}

func (a *Analyzer) FillServices(services *[]*common.Service) error {
	service := a.GetOrCreateWebService(services)
	service.Ports = []*common.PortMapping{common.NewPortMapping()}
	isRails, _ := common.GetGemVersion(a.Gemfile, "rails")

	if service.Command == "" {
		if isRails {
			service.Command = "bundle exec rails server -e _env:RAILS_ENV"
			service.Ports[0].Container = "3000"
		} else {
			service.Command = "bundle exec rackup -E _env:RACK_ENV"
			service.Ports[0].Container = "9292"
		}
		a.Messages.Add("No command was defined for 'web' service so '" + service.Command + "' was assumed. Please make sure this is using a production server.")
	} else {
		var err error
		hasFoundServer, server := a.detectWebServer(service.Command)
		service.Ports[0].Container, err = a.FindPort(hasFoundServer, server, &service.Command)

		if err != nil {
			return err
		}
	}

	if isRails {
		service.BuildCommand = a.AskForCommand("/bin/sh -c \"RAILS_ENV=_env:RAILS_ENV bundle exec rake db:schema:load\"", "build")
		service.DeployCommand = a.AskForCommand("/bin/sh -c \"RAILS_ENV=_env:RAILS_ENV bundle exec rake db:migrate\"", "deployment")
	} else {
		service.BuildCommand = a.AskForCommand("", "build")
		service.DeployCommand = a.AskForCommand("", "deployment")
	}
	for _, service := range *services {
		service.Tags = []string{"cloud66.framework:rails", "cloud66.language:ruby"}
	}
	return nil
}

func (a *Analyzer) HasPackage(pack string) bool {
	hasFound, _ := common.GetGemVersion(a.Gemfile, pack)
	return hasFound
}

func (a *Analyzer) detectWebServer(command string) (hasFound bool, server packs.WebServer) {
	unicorn := &webservers.Unicorn{}
	thin := &webservers.Thin{}
	servers := []packs.WebServer{unicorn, thin}
	return a.AnalyzerBase.DetectWebServer(a, command, servers)
}

func (a *Analyzer) GuessFramework() string {
	isRails, _ := common.GetGemVersion(a.Gemfile, "rails")
	if isRails {
		return "rails"
	}
	return ""
}

func (a *Analyzer) GuessPackages() *common.Lister {
	packages := common.NewLister()
	common.PrintlnL2("Analyzing dependencies")
	if hasRmagick, _ := common.GetGemVersion(a.Gemfile, "rmagick", "refile-mini_magick", "mini_magick"); hasRmagick {
		packages.Add("imagemagick", "libmagickwand-dev")
		common.PrintlnL2("Found Image Magick")
	}

	if hasSqlite, _ := common.GetGemVersion(a.Gemfile, "sqlite"); hasSqlite {
		packages.Add("libsqlite3-dev")
		common.PrintlnL2("Found sqlite")
	}

	if hasMemcache, _ := common.GetGemVersion(a.Gemfile, "dalli"); hasMemcache {
		packages.Add("memcached")
		common.PrintlnL2("Found Memcache")
	}
	return packages
}

func (a *Analyzer) FindVersion() string {
	foundRuby, rubyVersion := common.GetRubyVersion(a.Gemfile)
	return a.ConfirmVersion(foundRuby, rubyVersion, "latest")
}

func (a *Analyzer) FindDatabases() []common.Database {
	dbs := []common.Database{}

	if hasMysql, _ := common.GetGemVersion(a.Gemfile, "mysql2"); hasMysql {
		dbs = append(dbs, common.Database{Name: "mysql", DockerImage: "mysql"})
	}

	if hasPg, _ := common.GetGemVersion(a.Gemfile, "pg"); hasPg {
		dbs = append(dbs, common.Database{Name: "postgresql", DockerImage: "postgresql"})
	}

	if hasRedis, _ := common.GetGemVersion(a.Gemfile, "redis", "redis-rails"); hasRedis {
		dbs = append(dbs, common.Database{Name: "redis", DockerImage: "redis"})
	}

	if hasMongoDB, _ := common.GetGemVersion(a.Gemfile, "mongo", "mongo_mapper", "dm-mongo-adapter", "mongoid"); hasMongoDB {
		dbs = append(dbs, common.Database{Name: "mongodb", DockerImage: "mongo"})
	}

	if hasElasticsearch, _ := common.GetGemVersion(a.Gemfile, "elasticsearch", "tire", "flex", "chewy"); hasElasticsearch {
		dbs = append(dbs, common.Database{Name: "elasticsearch", DockerImage: "elasticsearch"})
	}

	if hasDatabaseYaml := common.FileExists("config/database.yml"); hasDatabaseYaml {
		common.PrintlnL2("Found config/database.yml")
		a.Messages.Add(
			fmt.Sprintf("%s %s-> %s",
				"database.yml: Make sure you are using environment variables.",
				common.MsgReset, "https://help.cloud66.com/skycap/tutorials/setting-environment-variables.html"))
	}

	if hasMongoIdYaml := common.FileExists("config/mongoid.yml"); hasMongoIdYaml {
		common.PrintlnL2("Found config/mongoid.yml")
		a.Messages.Add(
			fmt.Sprintf("%s %s-> %s",
				"mongoid.yml: Make sure you are using environment variables.",
				common.MsgReset, "https://help.cloud66.com/skycap/tutorials/setting-environment-variables.html"))
	}
	return dbs
}

func (a *Analyzer) EnvVars() []*common.EnvVar {
	return []*common.EnvVar{
		&common.EnvVar{Key: "SECRET_KEY_BASE", Value: "AUTO_GENERATE_128"},
		&common.EnvVar{Key: "RAILS_MASTER_KEY", Value: "AUTO_GENERATE_32"},
		&common.EnvVar{Key: "RAILS_ENV", Value: a.Environment},
		&common.EnvVar{Key: "RACK_ENV", Value: a.Environment}
	}
}
