SMTP_TEST_LIB_SRCS = \
	netx_smtp_basic_function_test.c \
	smtp_250_ehlo_first_pkt.c \
	smtp_250_ehlo_last_pkt.c \
	smtp_250_ehlo_ok_pkt.c \
	smtp_220_greetings_ok.c \
	smtp_334_pkt.c \
	smtp_235_auth_passed.c \
	smtp_250_sender_ok.c \
	smtp_250_recipient_ok.c \
	smtp_354_enter_mail_pkt.c \
	smtp_250_message_saved.c \
	smtp_221_bye_pkt.c \
 
SMTP_TEST_LIB_OBJS = $(SMTP_TEST_LIB_SRCS:.c=.obj) 
