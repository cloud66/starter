package docker_compose

type Resources struct {
	Memory int `yaml:"memory,omitempty"`
	Cpu    int  `yaml:"cpu,omitempty"`
}