if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882068" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-22 06:02:49 +0200 (Wed, 22 Oct 2014)" );
	script_cve_id( "CVE-2014-3634" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for rsyslog5 CESA-2014:1671 centos5" );
	script_tag( name: "summary", value: "Check the version of rsyslog5" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The rsyslog packages provide an enhanced,
multi-threaded syslog daemon that supports writing to relational databases,
syslog/TCP, RFC 3195, permitted sender lists, filtering on any message part,
and fine grained output format control.

A flaw was found in the way rsyslog handled invalid log message priority
values. In certain configurations, a local attacker, or a remote attacker
able to connect to the rsyslog port, could use this flaw to crash the
rsyslog daemon. (CVE-2014-3634)

Red Hat would like to thank Rainer Gerhards of rsyslog upstream for
reporting this issue.

All rsyslog5 and rsyslog users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue. After
installing the update, the rsyslog service will be restarted automatically." );
	script_tag( name: "affected", value: "rsyslog5 on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:1671" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-October/020699.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "rsyslog5", rpm: "rsyslog5~5.8.12~5.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog5-gnutls", rpm: "rsyslog5-gnutls~5.8.12~5.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog5-gssapi", rpm: "rsyslog5-gssapi~5.8.12~5.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog5-mysql", rpm: "rsyslog5-mysql~5.8.12~5.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog5-pgsql", rpm: "rsyslog5-pgsql~5.8.12~5.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog5-snmp", rpm: "rsyslog5-snmp~5.8.12~5.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

