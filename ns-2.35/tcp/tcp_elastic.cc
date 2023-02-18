/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */



#ifndef lint
static const char rcsid[] =
"@(#) $Header: /cvsroot/nsnam/ns-2/tcp/tcp-vegas.cc,v 1.37 2005/08/25 18:58:12 johnh Exp $ (NCSU/IBM)";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <math.h>
#include "ip.h"
#include "tcp.h"
#include "flags.h"

#define MIN(x, y) ((x)<(y) ? (x) : (y))
#define DEBUG false


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


void
ElasticTcpAgent::recv(Packet *pkt, Handler *)
{
	hdr_tcp *tcph = hdr_tcp::access(pkt);
	int valid_ack = 0;
	printf("cwnd_ in recv: %lf\n",cwnd_.getVal());
	
	if (tcph->ts() < lastreset_) {
		// Remove packet and do nothing
		Packet::free(pkt);
		return;
	}
	++nackpack_;
	ts_peer_ = tcph->ts();

	if(tcph->seqno() > last_ack_){
		//write code here
		recv_newack_helper(pkt);
	} else if(tcph->seqno() == last_ack_){
		if (++dupacks_ == numdupacks_ && !noFastRetrans_) {
			dupack_action();
		} else if (dupacks_ < numdupacks_ && singledup_ ) {
			send_one();
		}
	}

	if (tcph->seqno() >= last_ack_)  
		valid_ack = 1;
	Packet::free(pkt);
	if (valid_ack || aggressive_maxburst_)
		send_much(0, 0, maxburst_);
}
void
ElasticTcpAgent::recv_newack_helper(Packet* pkt){
	newack(pkt);
	if(!ect_){
		if(!control_increase_ || (control_increase_ && (network_limited() == 1)))
		{
			opencwnd();
		}
	}
	if((highest_ack_ >= curseq_ -1) && !closed_){
		closed_ = 1;
		finish();
	}
}

void
ElasticTcpAgent::opencwnd()
{
	double increment;
	if (cwnd_ < ssthresh_) {
		printf("Inside slow-start, Current cwnd: %f, ssthresh: %d \n",double(cwnd_), int(ssthresh_));
		/* slow-start (exponential) */
		cwnd_ += 1;
	} else {
		/* linear */
		double f;
		if(DEBUG) printf("wnd_option_ is : %d\n",wnd_option_);
		if(DEBUG && wnd_option_ > 1) printf("-----------wnd_option_ is not one here-----------\n");
		switch (wnd_option_) {
		case 0:
			if (++count_ >= cwnd_) {
				count_ = 0;
				++cwnd_;
			}
			break;

		case 1:
			if( t_rtt_ < baseRTT_ ) baseRTT_ = t_rtt_;
			if( t_rtt_ > maxRTT_ ) maxRTT_ = t_rtt_;
			if(DEBUG) printf("RTT: %lf\n", (double) t_rtt_);
			if(DEBUG) printf("MAX RTT: %lf\n", (double) maxRTT_);
			if(DEBUG) printf("Base RTT: %lf\n",(double) baseRTT_);
			printf("cwnd_ before: %lf\n",cwnd_.getVal());
			// double wwf = sqrt( ( (double)maxRTT_ / (double)t_rtt_ ) * (double) cwnd_ );
			printf("adding: %lf\n",sqrt(( ( (double)maxRTT_ / (double)t_rtt_ ) * (double) cwnd_ )) / cwnd_);
			cwnd_ = cwnd_ + ((sqrt(( ( (double)maxRTT_ / (double)t_rtt_ ) * (double) cwnd_ ))) / cwnd_);
			printf("cwnd_ after: %lf\n",(double)cwnd_);
			break;

		case 2:
			/* These are window increase algorithms
			 * for experimental purposes only. */
			/* This is the Constant-Rate increase algorithm 
                         *  from the 1991 paper by S. Floyd on "Connections  
			 *  with Multiple Congested Gateways". 
			 *  The window is increased by roughly 
			 *  wnd_const_*RTT^2 packets per round-trip time.  */
			f = (t_srtt_ >> T_SRTT_BITS) * tcp_tick_;
			f *= f;
			f *= wnd_const_;
			/* f = wnd_const_ * RTT^2 */
			f += fcnt_;
			if (f > cwnd_) {
				fcnt_ = 0;
				++cwnd_;
			} else
				fcnt_ = f;
			break;

		case 3:
			/* The window is increased by roughly 
			 *  awnd_^2 * wnd_const_ packets per RTT,
			 *  for awnd_ the average congestion window. */
			f = awnd_;
			f *= f;
			f *= wnd_const_;
			f += fcnt_;
			if (f > cwnd_) {
				fcnt_ = 0;
				++cwnd_;
			} else
				fcnt_ = f;
			break;

                case 4:
			/* The window is increased by roughly 
			 *  awnd_ * wnd_const_ packets per RTT,
			 *  for awnd_ the average congestion window. */
                        f = awnd_;
                        f *= wnd_const_;
                        f += fcnt_;
                        if (f > cwnd_) {
                                fcnt_ = 0;
                                ++cwnd_;
                        } else
                                fcnt_ = f;
                        break;
		case 5:
			/* The window is increased by roughly wnd_const_*RTT 
			 *  packets per round-trip time, as discussed in
			 *  the 1992 paper by S. Floyd on "On Traffic 
			 *  Phase Effects in Packet-Switched Gateways". */
                        f = (t_srtt_ >> T_SRTT_BITS) * tcp_tick_;
                        f *= wnd_const_;
                        f += fcnt_;
                        if (f > cwnd_) {
                                fcnt_ = 0;
                                ++cwnd_;
                        } else
                                fcnt_ = f;
                        break;
                case 6:
                        /* binomial controls */ 
                        cwnd_ += increase_num_ / (cwnd_*pow(cwnd_,k_parameter_));                
                        break; 
 		case 8: 
			/* high-speed TCP, RFC 3649 */
			increment = increase_param();
			if ((last_cwnd_action_ == 0 ||
			  last_cwnd_action_ == CWND_ACTION_TIMEOUT) 
			  && max_ssthresh_ > 0) {
				increment = limited_slow_start(cwnd_,
				  max_ssthresh_, increment);
			}
			cwnd_ += increment;
                        break;
		default:
#ifdef notdef
			/*XXX*/
			error("illegal window option %d", wnd_option_);
#endif
			abort();
		}
	}
	// if maxcwnd_ is set (nonzero), make it the cwnd limit
	if (maxcwnd_ && (int(cwnd_) > maxcwnd_))
		cwnd_ = maxcwnd_;

	return;
}

