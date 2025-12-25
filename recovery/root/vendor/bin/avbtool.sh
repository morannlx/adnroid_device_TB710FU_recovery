#!/sbin/sh

chmod 777 /customzip/python_env/python
chmod 777 /customzip/python_env/python.sh
chmod 777 /system/bin/openssl
chmod 777 /customzip/avbtool/sign_boot.sh
chmod 777 /customzip/avbtool/sign.sh 

mv /customzip/python_env/python.sh /sbin/python
mv /customzip/python_env /
mv /customzip/avbtool /


exit 0