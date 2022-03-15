if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2305" );
	script_cve_id( "CVE-2017-16808", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14879", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16301", "CVE-2018-16451", "CVE-2018-16452", "CVE-2018-19519", "CVE-2019-1010220", "CVE-2019-15166" );
	script_tag( name: "creation_date", value: "2020-01-23 12:45:59 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-11 23:15:00 +0000 (Fri, 11 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for tcpdump (EulerOS-SA-2019-2305)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2305" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2305" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'tcpdump' package(s) announced via the EulerOS-SA-2019-2305 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "tcpdump before 4.9.3 has a heap-based buffer over-read related to aoe_print in print-aoe.c and lookup_emem in addrtoname.c.(CVE-2017-16808)

The FRF.16 parser in tcpdump before 4.9.3 has a buffer over-read in print-fr.c:mfr_print().(CVE-2018-14468)

The IKEv1 parser in tcpdump before 4.9.3 has a buffer over-read in print-isakmp.c:ikev1_n_print().(CVE-2018-14469)

The Babel parser in tcpdump before 4.9.3 has a buffer over-read in print-babel.c:babel_print_v2().(CVE-2018-14470)

The Rx parser in tcpdump before 4.9.3 has a buffer over-read in print-rx.c:rx_cache_find() and rx_cache_insert().(CVE-2018-14466)

The LDP parser in tcpdump before 4.9.3 has a buffer over-read in print-ldp.c:ldp_tlv_print().(CVE-2018-14461)

The ICMP parser in tcpdump before 4.9.3 has a buffer over-read in print-icmp.c:icmp_print().(CVE-2018-14462)

The RSVP parser in tcpdump before 4.9.3 has a buffer over-read in print-rsvp.c:rsvp_obj_print().(CVE-2018-14465)

The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print() (BGP_CAPCODE_RESTART).(CVE-2018-14881)

The LMP parser in tcpdump before 4.9.3 has a buffer over-read in print-lmp.c:lmp_print_data_link_subobjs().(CVE-2018-14464)

The VRRP parser in tcpdump before 4.9.3 has a buffer over-read in print-vrrp.c:vrrp_print().(CVE-2018-14463)

The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print() (BGP_CAPCODE_MP).(CVE-2018-14467)

tcpdump before 4.9.3 mishandles the printing of SMB data (issue 1 of 2).(CVE-2018-10103)

tcpdump before 4.9.3 mishandles the printing of SMB data (issue 2 of 2).(CVE-2018-10105)

The OSPFv3 parser in tcpdump before 4.9.3 has a buffer over-read in print-ospf6.c:ospf6_print_lshdr().(CVE-2018-14880)

The SMB parser in tcpdump before 4.9.3 has buffer over-reads in print-smb.c:print_trans() for \\MAILSLOT\\BROWSE and \\PIPE\\LANMAN.(CVE-2018-16451)

The ICMPv6 parser in tcpdump before 4.9.3 has a buffer over-read in print-icmp6.c.(CVE-2018-14882)

The IEEE 802.11 parser in tcpdump before 4.9.3 has a buffer over-read in print-802_11.c for the Mesh Flags subfield.(CVE-2018-16227)

The DCCP parser in tcpdump before 4.9.3 has a buffer over-read in print-dccp.c:dccp_print_option().(CVE-2018-16229)

libpcap before 1.9.1, as used in tcpdump before 4.9.3, has a buffer overflow and/or over-read because of errors in pcapng reading.(CVE-2018-16301)

The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_attr_print() (MP_REACH_NLRI).(CVE-2018-16230)

The SMB parser in tcpdump before 4.9.3 has stack exhaustion in smbutil.c:smb_fdata() via recursion.(CVE-2018-16452)

The BGP parser in tcpdump before 4.9.3 allows stack consumption in print-bgp.c:bgp_attr_print() because of unlimited recursion.(CVE-2018-16300)

The HNCP parser in tcpdump before 4.9.3 has a buffer over-read in ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'tcpdump' package(s) on Huawei EulerOS V2.0SP8." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "EULEROS-2.0SP8"){
	if(!isnull( res = isrpmvuln( pkg: "tcpdump", rpm: "tcpdump~4.9.3~1.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

