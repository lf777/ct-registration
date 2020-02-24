mach_name=$(hostname)
data_dir=~/dev-py/ct2/postgres-data_${mach_name}
mkdir -p $data_dir

sudo docker run -d --name pg_ct -e POSTGRES_PASSWORD=P@ssw0rd12345 -p 15243:5432 -v ~/dev-py/ct2:/server -v ${data_dir}:/var/lib/postgresql/data postgres:12.1-alpine
