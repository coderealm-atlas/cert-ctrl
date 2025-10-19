[Unit]
Description=Cert issue Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/apps/certctrl
ExecStart=/opt/apps/certctrl/certctrl --config /opt/apps/certctrl/config.json --keep-running
EnvironmentFile=/opt/apps/certctrl/app.env
Restart=on-failure
User=root
Group=root

[Install]
WantedBy=multi-user.target
