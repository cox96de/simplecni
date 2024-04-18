# SimpleCNI

`simplecni` is a streamlined CNI plugin for Kubernetes, specifically designed for simplicity and usability in
environments
where the complexity of other CNI plugins is unnecessary.

With proven stability for production use, it efficiently
manages clusters with over 1000 nodes.

This project is also a great starting point for anyone looking to learn about CNI plugins.

**Dual-stack is supported**

## Installation

There are no strict requirements for pod, service, or node CIDR ranges.

```shell
kubectl apply -f https://raw.githubusercontent.com/cox96de/simplecni/master/installation.yaml
```

## [How it works](https://cox96de.notion.site/Write-a-simple-CNI-plugin-35507da863dc4c20943b30400924e719?pvs=74)
