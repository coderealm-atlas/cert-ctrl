[Unit]
Description=Cert issue Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/apps/certctrl
ExecStart=/opt/apps/certctrl/certctrl --config /opt/apps/certctrl/config.json
EnvironmentFile=/opt/apps/certctrl/app.env
Restart=on-failure
User=jianglibo
Group=jianglibo

[Install]
WantedBy=multi-user.target
