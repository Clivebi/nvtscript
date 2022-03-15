if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882499" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-03 16:25:05 +0530 (Fri, 03 Jun 2016)" );
	script_cve_id( "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556", "CVE-2009-0801" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for squid CESA-2016:1139 centos7" );
	script_tag( name: "summary", value: "Check the version of squid" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Squid is a high-performance proxy caching
server for web clients, supporting FTP, Gopher, and HTTP data objects.

Security Fix(es):

  * A buffer overflow flaw was found in the way the Squid cachemgr.cgi
utility processed remotely relayed Squid input. When the CGI interface
utility is used, a remote attacker could possibly use this flaw to execute
arbitrary code. (CVE-2016-4051)

  * Buffer overflow and input validation flaws were found in the way Squid
processed ESI responses. If Squid was used as a reverse proxy, or for
TLS/HTTPS interception, a remote attacker able to control ESI components on
an HTTP server could use these flaws to crash Squid, disclose parts of the
stack memory, or possibly execute arbitrary code as the user running Squid.
(CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

  * An input validation flaw was found in the way Squid handled intercepted
HTTP Request messages. An attacker could use this flaw to bypass the
protection against issues related to CVE-2009-0801, and perform cache
poisoning attacks on Squid. (CVE-2016-4553)

  * An input validation flaw was found in Squid's mime_get_header_field()
function, which is used to search for headers within HTTP requests. An
attacker could send an HTTP request from the client side with specially
crafted header Host header that bypasses same-origin security protections,
causing Squid operating as interception or reverse-proxy to contact the
wrong origin server. It could also be used for cache poisoning for client
not following RFC 7230. (CVE-2016-4554)

  * A NULL pointer dereference flaw was found in the way Squid processes ESI
responses. If Squid was used as a reverse proxy or for TLS/HTTPS
interception, a malicious server could use this flaw to crash the Squid
worker process. (CVE-2016-4555)

  * An incorrect reference counting flaw was found in the way Squid processes
ESI responses. If Squid is configured as reverse-proxy, for TLS/HTTPS
interception, an attacker controlling a server accessed by Squid, could
crash the squid worker, causing a Denial of Service attack. (CVE-2016-4556)" );
	script_tag( name: "affected", value: "squid on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1139" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-May/021900.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "squid", rpm: "squid~3.3.8~26.el7_2.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "squid-sysvinit", rpm: "squid-sysvinit~3.3.8~26.el7_2.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

