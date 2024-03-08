diesel_cli is a orm-framework, now we can use diesel_cli to ouput struct & dsl with sql files.

# 1. Setup Env

we need to define mysqlclient.lib in the ENV. 

example in linux:
``` shell
export MYSQLCLIENT_LIB_DIR="your path to mysqlclient.lib"
```

example in windows:
``` shell
setx MYSQLCLIENT_LIB_DIR "your path to mysqlclient.lib"
```

# 2. Install diesel_cli

now we can use cargo to install diesel_cli, if you will not use the client to output sql structs, then skip this step.

``` shell
cargo install diesel_cli --no-default-features --features mysql
```

# 3. Import diesel into the project

open the cargo.toml and add dependencies like this:

```
[dependencies]
# other dependencies
diesel = { version = "2.1.4", features = ["mysql", "r2d2"] }
r2d2 = "0.8.9"
r2d2-diesel = "1.0.0"
```

Now you can use diesel to run this project.

if you need to edit sql or structs. maybe you need step 4

# 4. Use diesel_cli to output structs with sql

``` shell
cd /path/to/project/root
diesel setup --database-url="mysql://[username:[password]]@[host:[port]]/[database]"
diesel migration generate your_sql_summary --database-url="mysql://[username:[password]]@[host:[port]]/[database]"
diesel migration run "mysql://[username:[password]]@[host:[port]]/[database]
```

then run the unit test with mysqlbackend

# Issues still need to optimize

- tlsconnection to mysql
- connection to postgre