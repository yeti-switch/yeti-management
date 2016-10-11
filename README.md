# yeti-management

yeti-management is a part of project [Yeti]

## Build (Debian 8/9)

### install build dependencies

```sh
# aptitude install libprotobuf-dev libnanomsg-dev libconfuse-dev
```

### get sources & build

```sh
$ git clone https://github.com/yeti-switch/yeti-management.git
$ cd yeti-management
$ mkdir build && cd build
$ cmake ..
$ make
```

### make debian packages
```sh
$ make deb
```

you will get three packages:

* _libyeticc_ contains so library
* _libyeticc-dev_ contains library header, data for pkgconfig, cmake helper to use in projects to find library 
* _yeti-management_ contains configuration server daemon

[Yeti]:http://yeti-switch.org/
