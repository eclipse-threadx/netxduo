#! /bin/sh
#


mosquitto_sub --cert 643ad617ec-certificate.pem.crt --key 643ad617ec-private.pem.key --cafile ca.pem -h a1m35stuxxwf0e.iot.us-west-2.amazonaws.com -p 8883 $*
