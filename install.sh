mkdir -p /data/src
cd /data/src
if [ ! -x "LuaJIT-2.0.5.tar.gz" ]; then  
wget http://luajit.org/download/LuaJIT-2.0.5.tar.gz
fi
tar zxvf LuaJIT-2.0.5.tar.gz
cd LuaJIT-2.0.5
make
make install PREFIX=/usr/local/lj2
ln -s /usr/local/lj2/lib/libluajit-5.1.so.2 /lib64/
cd /data/src
if [ ! -x "v0.3.1.tar.gz" ]; then  
wget https://github.com/vision5/ngx_devel_kit/archive/v0.3.1.tar.gz
fi
tar zxvf v0.3.1.tar.gz
if [ ! -x "v0.10.15.tar.gz" ]; then  
wget https://github.com/openresty/lua-nginx-module/archive/v0.10.15.tar.gz
fi
tar zxvf v0.10.15.tar.gz
cd /data/src
if [ ! -x "pcre-8.44.tar.gz" ]; then
wget https://ftp.pcre.org/pub/pcre/pcre-8.44.tar.gz
fi
tar zxvf pcre-8.44.tar.gz
cd pcre-8.44/
./configure
make && make install
cd -


#if [ ! -x "nginx-1.2.4.tar.gz" ]; then
#wget 'http://nginx.org/download/nginx-1.2.4.tar.gz'
#fi
#tar -xzvf nginx-1.2.4.tar.gz
#cd nginx-1.2.4/
#export LUAJIT_LIB=/usr/local/lj2/lib/
#export LUAJIT_INC=/usr/local/lj2/include/luajit-2.0/
#./configure --user=daemon --group=daemon --prefix=/usr/local/nginx/ --with-http_stub_status_module --with-http_sub_module --with-http_gzip_static_module --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module  --add-module=../ngx_devel_kit-0.2.17rc2/ --add-module=../lua-nginx-module-0.7.4/
#make -j8
#make install 
#rm -rf /data/src


cd /usr/local/nginx/conf/
wget https://github.com/gikoluo/ngx_lua_waf/archive/master.zip --no-check-certificate
unzip master.zip
mv ngx_lua_waf-master/* /usr/local/nginx/conf/
rm -rf ngx_lua_waf-master
rm -rf /data/src
mkdir -p /data/logs/hack
chmod -R 775 /data/logs/hack
