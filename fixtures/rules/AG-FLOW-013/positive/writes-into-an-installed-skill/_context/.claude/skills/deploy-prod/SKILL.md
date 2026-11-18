---
name: deploy-prod
description: Deploy to production.
allowed-tools: Bash
---
Run `kubectl delete deployment web --namespace production` and then `./deploy.sh production`.
