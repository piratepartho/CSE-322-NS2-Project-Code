/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */



#ifndef lint
static const char rcsid[] =
"@(#) $Header: /cvsroot/nsnam/ns-2/tcp/tcp-vegas.cc,v 1.37 2005/08/25 18:58:12 johnh Exp $ (NCSU/IBM)";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "ip.h"
#include "tcp.h"
#include "flags.h"

#define MIN(x, y) ((x)<(y) ? (x) : (y))


static class ElasticTcpClass : public TclClass {
public:
	ElasticTcpClass() : TclClass("Agent/TCP/Elastic") {}
	TclObject* create(int, const char*const*) {
		return (new ElasticTcpAgent());
	}
} class_elastic;

ElasticTcpAgent::ElasticTcpAgent() : TcpAgent(){
	baseRTT_ = __INT_MAX__;
	maxRTT_ = 0;
}

ElasticTcpAgent::~ElasticTcpAgent() {}

void
ElasticTcpAgent::delay_bind_init_all()
{
	delay_bind_init_one("baseRTT_");
	delay_bind_init_one("maxRTT_");
	TcpAgent::delay_bind_init_all();
    reset();
}

void 
ElasticTcpAgent::rtt_init(){
	baseRTT_ = __INT_MAX__;
	maxRTT_ = 0;
	TcpAgent::rtt_init();
}

int
ElasticTcpAgent::delay_bind_dispatch(const char *varName, const char *localName, TclObject *tracer)
{
	/* init vegas var */
        if (delay_bind(varName, localName, "baseRTT_", &baseRTT_, tracer)) 
		return TCL_OK;
        if (delay_bind(varName, localName, "maxRTT_", &maxRTT_, tracer)) 
		return TCL_OK;
        return TcpAgent::delay_bind_dispatch(varName, localName, tracer);
}

void
ElasticTcpAgent::reset()
{
	baseRTT_ = __INT_MAX__;
	maxRTT_ = 0;

	TcpAgent::reset();
}

// void
// VegasTcpAgent::recv_newack_helper(Packet *pkt)
// {
// 	newack(pkt);
// #if 0
// 	// like TcpAgent::recv_newack_helper, but without this
// 	if ( !hdr_flags::access(pkt)->ecnecho() || !ecn_ ) {
// 	        opencwnd();
// 	}
// #endif
// 	/* if the connection is done, call finish() */
// 	if ((highest_ack_ >= curseq_-1) && !closed_) {
// 		closed_ = 1;
// 		finish();
// 	}
// }

void
ElasticTcpAgent::recv(Packet *pkt, Handler *)
{
	hdr_tcp *tcph = hdr_tcp::access(pkt);
	int valid_ack = 0;
	if(qs_approved_ == 1 && tcph->seqno() > last_ack_){
		endQuickStart();
	}
	if(qs_requested_ == 1){
		processQuickStart(pkt);
	}
	if (tcph->ts() < lastreset_) {
		// Remove packet and do nothing
		Packet::free(pkt);
		return;
	}
	++nackpack_;
	ts_peer_ = tcph->ts();
	int ecnecho = hdr_flags::access(pkt)->ecnecho();
	if (ecnecho && ecn_)
		ecn(tcph->seqno());
	recv_helper(pkt);
	recv_frto_helper(pkt);

	if(tcph->seqno() > last_ack_){
		//write code here
	}
	else if(tcph->seqno() == last_ack_){
		if (hdr_flags::access(pkt)->eln_ && eln_) {
                        tcp_eln(pkt);
                        return;
        }
		if (++dupacks_ == numdupacks_ && !noFastRetrans_) {
			dupack_action();
		} else if (dupacks_ < numdupacks_ && singledup_ ) {
			send_one();
		}
	}

	if (QOption_ && EnblRTTCtr_)
		process_qoption_after_ack (tcph->seqno());

	if (tcph->seqno() >= last_ack_)  
		// Check if ACK is valid.  Suggestion by Mark Allman. 
		valid_ack = 1;
	Packet::free(pkt);
	/*
	 * Try to send more data.
	 */
	if (valid_ack || aggressive_maxburst_)
		send_much(0, 0, maxburst_);
}


