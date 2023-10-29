#!/usr/bin/env python3
import sys
import requests
import json
import os
import urllib3 # urllib3 is a transitive dependency of requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DOCKER_HUB_REGISTRY = 'registry.hub.docker.com'

PROTOCOL_SUCCEED = None
AUTH_TYPE = "Bearer" # default, could be something else
AUTH_TOKEN = None
AUTH_HEADER = None
REPO = None
REGISTRY = None
TAG = None

def get_registry_from_image(image: str):
	'''
	ubuntu:latest -> no registry
	ghcr.io/namespace/image:latest -> ghcr.io
	localhost:5000/library/alpine -> localhost:5000

	returns string of registry domain or None
	'''
	elements_slash_separated = image.split('/')
	if len(elements_slash_separated) <= 2:
		return None
	return elements_slash_separated[0]

def get_ref_tag_from_image(image: str):
	if len(image.split(":")) <= 1:
		return None
	return image.split(":")[1]

def get_repo_from_image(image: str):
	'''
	localhost:5000/library/alpine -> library/alpine
	ubuntu:latest -> library/ubuntu
	'''
	if get_registry_from_image(image) == None:
		if '/' not in image:
			return 'library/' + image.split(":")[0]
		else:
			return image.split(":")[0]
	else:
		if '/' not in image:
			return 'library/' + image.split(":")[0]
		return '/'.join(image.split("/")[1:]).split(":")[0]


def get_manifest(image: str, auth=None):
	global REPO, REGISTRY, AUTH_TOKEN, AUTH_TYPE, TAG, AUTH_HEADER, PROTOCOL_SUCCEED

	# auth: basic auth tuple, optional

	# nice article explaining it: https://www.redhat.com/architect/pull-container-image
	# GET /v2/<repo>/<image>/manifests/<tag>
	# example:
	# GET /v2/library/postgres/manifests/14

	# list all images in a registry (wont work for dockerhub..?): curl http://somehost/v2/_catalog
	# GET /v2/<repository>/tags/list for getting all tags for that repo

	REGISTRY = get_registry_from_image(image)
	if REGISTRY == None:
		print(f"assuming {DOCKER_HUB_REGISTRY} as registry")
		REGISTRY = DOCKER_HUB_REGISTRY # assume docker hub
	print('registry:', REGISTRY)

	TAG = get_ref_tag_from_image(image)
	if TAG == None:
		print("assuming latest as tag since none specified")
		TAG = "latest"
	print('tag:', TAG)

	REPO = get_repo_from_image(image)
	print('repo:', REPO)

	www_authenticate = None

	# check if auth is required
	try: # try https first
		r = requests.get(f'https://{REGISTRY}/v2/', verify=False)
		PROTOCOL_SUCCEED = 'https'
		if r.status_code == 401:
			www_authenticate = r.headers['Www-Authenticate']
			print("Auth required, www_authenticate:", www_authenticate)
		elif r.status_code != 200:
			print("bad status code on registry:", r.status_code, r.text)


	except requests.exceptions.SSLError as e:
		print("error using https url, using http")
		PROTOCOL_SUCCEED = 'http'
		r = requests.get(f'http://{REGISTRY}/v2/')
		if r.status_code == 401:
			www_authenticate = r.headers['Www-Authenticate']
			print("Auth required, www_authenticate:", www_authenticate)
		elif r.status_code != 200:
			print("bad status code on registry:", r.status_code, r.text)

	if www_authenticate:
		# e.g. Bearer
		AUTH_TYPE =  www_authenticate.split()[0]
		auth_endpoint = www_authenticate.split()[1].split('realm="')[1].split('"')[0]
		auth_service = www_authenticate.split()[1].split('service="')[1].split('"')[0]
		r = requests.get(f'{auth_endpoint}?scope=repository:{REPO}:pull&service={auth_service}', verify=False)
		if r.status_code != 200:
			print("could not get auth token from registry:", r.status_code, r.text)
			exit(1)
		try:
			# WTF, why is there ambiguity here!!!?? bloody OAuth
			# pick one damn it

			if "token" in r.json(): 
				AUTH_TOKEN = r.json()['token']
			elif "access_token" in r.json():
				AUTH_TOKEN = r.json()['access_token']
			if not AUTH_TOKEN:
				print("something wrong with getting token:", r.text)
			AUTH_HEADER = f"{AUTH_TYPE} {AUTH_TOKEN}"
			print("got auth header:", AUTH_HEADER[:20]+"...(snipped)")
		except KeyError as e:
			print("failed to get access_token:", r.status_code, r.text)


	manifest = None
	

	# try https first
	try:
		url = f"https://{REGISTRY}/v2/{REPO}/manifests/{TAG}"
		print("getting manifest url:", url)

		if AUTH_HEADER:
			r = requests.get(url, timeout=3, headers={"Authorization":AUTH_HEADER}, verify=False) # verify=False if you need self signed certs
		else:
			r = requests.get(url, timeout=3)

		PROTOCOL_SUCCEED = "https"
		manifest = r.json()


	except requests.exceptions.SSLError as e:
		
		print("trying http next")
		url =  f"http://{REGISTRY}/v2/{REPO}/manifests/{TAG}"
		print("getting manifest url:", url)

		if AUTH_HEADER:
			r = requests.get(url, timeout=3, headers={"Authorization":AUTH_HEADER})
		r = requests.get(url, timeout=3)
		PROTOCOL_SUCCEED = "http"
		manifest = r.json()


	if PROTOCOL_SUCCEED == None:
		print("Fatal: failed getting manifest")
		exit(1)

	if "manifests" in manifest: # manifest list
		# select the first one for now, it's most likely amd64
		print("manifest list detected, selecting first one")
		print("platform:", manifest["manifests"][0]["platform"])
		digest = manifest["manifests"][0]["digest"]
		media_type =  manifest["manifests"][0]["mediaType"]
		url = f"{PROTOCOL_SUCCEED}://{REGISTRY}/v2/{REPO}/manifests/{digest}"
		headers = {"Accept":media_type}
		if AUTH_HEADER:
			headers["Authorization"] = AUTH_HEADER

		print("media type:", media_type)
		print("chosen manifest url:", url)
		r = requests.get(url, timeout=3, headers=headers, verify=False) # verify=False if you need self signed certs
		manifest = r.json()


	print(json.dumps(manifest, indent=2))
	return manifest


def stream_download(url, headers, filename):
	with requests.get(url, headers=headers, stream=True) as r:
		written_so_far = 0
		chunk_size = 10 * 1024 * 1024
		with open(filename, 'wb') as f:
			total_size = int(r.headers['Content-Length'])
			# pbar = tqdm(total=int(r.headers['Content-Length']))
			for chunk in r.iter_content(chunk_size=chunk_size):
				if chunk:  # filter out keep-alive new chunks
					f.write(chunk)
					written_so_far += len(chunk)
					print(f"progress on {filename}: {(written_so_far/total_size)*100}%")
		print(f"done for {filename}, total size {total_size} ({total_size/1000000}MB)")

def download_layers(manifest, download_dir):
	print("getting layers..")
	layer_digest_sizes = {} # digest as key, size as value
	layer_digest_mediatypes = {}
	
	if manifest["schemaVersion"] == 2 and "layers" in manifest: # v2
		for layer in manifest["layers"]:
			# start from the smallest file
			layer_digest_sizes[layer['digest']] = layer['size']
			layer_digest_mediatypes[layer['digest']] = layer['mediaType']


		# download from the smallest layer first
		for digest, size in sorted(layer_digest_sizes.items(), key=lambda item: item[1]):
			url = f"{PROTOCOL_SUCCEED}://{REGISTRY}/v2/{REPO}/blobs/{digest}"
			headers = {"Accept":layer_digest_mediatypes[digest]}
			if AUTH_HEADER:
				headers['Authorization'] = AUTH_HEADER

			filename = os.path.join(download_dir, digest.split(":")[1]+".tgz")  # assume tgz, most of the time
			stream_download(url, headers, filename)

	elif manifest["schemaVersion"] == 1 and "fsLayers" in manifest: #v1
		# no size info available
		for layer in manifest["fsLayers"]:
			digest = layer["blobSum"]
			url = f"{PROTOCOL_SUCCEED}://{REGISTRY}/v2/{REPO}/blobs/{digest}"
			headers = {}
			if AUTH_HEADER:
				headers['Authorization'] = AUTH_HEADER
			filename = os.path.join(download_dir, digest.split(":")[1]+".tgz")
			stream_download(url, headers, filename)

	else:
		print("not supported:", manifest["schemaVersion"], "keys:", manifest.keys())






def main():
	if len(sys.argv) < 2:
		print("Usage: %s <image>" %sys.argv[0])
		print("Examples:")
		print("%s alpine:latest")
		print("%s localhost:5000/ubuntu:latest")
		print("%s gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine")
	image = sys.argv[1]
	manifest = get_manifest(image)
	# parse manifest
	# for schema v2, config, layers
	# for schama v1, fsLayers, history
	schema_version = manifest["schemaVersion"]

	download_dir = os.path.join('downloads', REGISTRY, REPO.split('/')[0], REPO.split('/')[1], TAG)
	if not os.path.exists(os.path.join('downloads', REGISTRY)):
		to_mkdir = os.path.join('downloads', REGISTRY)
		print("mkdir", to_mkdir)
		os.mkdir(to_mkdir)
		
	if not os.path.exists(os.path.join('downloads', REGISTRY, REPO.split('/')[0])):
		to_mkdir = os.path.join('downloads', REGISTRY, REPO.split('/')[0])
		print("mkdir", to_mkdir)
		os.mkdir(to_mkdir)

	if not os.path.exists(os.path.join('downloads', REGISTRY, REPO.split('/')[0], REPO.split('/')[1])):
		to_mkdir = os.path.join('downloads', REGISTRY, REPO.split('/')[0], REPO.split('/')[1])
		print("mkdir", to_mkdir)
		os.mkdir(to_mkdir)

	if not os.path.exists(download_dir):
		to_mkdir = os.path.join(download_dir)
		print("mkdir", to_mkdir)
		os.mkdir(to_mkdir)
	
	if not os.path.exists(download_dir):
		print("ERROR: download dir does not exist, could not be created:", download_dir)

	with open(os.path.join(download_dir,"manifest.json"),"w+") as f:
		json.dump(manifest,f)
	print('written manifest.json to', os.path.join(download_dir,"manifest.json"))

	if schema_version == 2:
		# download config
		if "config" in manifest:
			print("getting config..")
			digest =  manifest['config']['digest']
			digest_sum = manifest['config']['digest'].split(":")[1]

			url = f"{PROTOCOL_SUCCEED}://{REGISTRY}/v2/{REPO}/blobs/{digest}"
			headers = {"Accept":manifest['config']['mediaType']}
			if AUTH_HEADER:
				headers["Authorization"] = AUTH_HEADER
			r = requests.get(url, headers=headers)
			config = r.json()
			print("-------- config ----------")
			print(json.dumps(config, indent=2))
			
			config_dir = os.path.join(download_dir, digest_sum)
			if not os.path.exists(config_dir):
				os.mkdir(config_dir)
			with open(os.path.join(config_dir,'json'), 'w+') as f:
				json.dump(config, f, indent=2)
			print("written config to", os.path.join(config_dir,'json'))

	download_layers(manifest, download_dir)









if __name__ == '__main__':
	main()
