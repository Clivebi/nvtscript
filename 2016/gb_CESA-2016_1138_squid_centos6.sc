if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882497" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-03 16:25:06 +0530 (Fri, 03 Jun 2016)" );
	script_cve_id( "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4554", "CVE-2016-4556" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for squid CESA-2016:1138 centos6" );
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

  * An input validation flaw was found in Squid's mime_get_header_field()
function, which is used to search for headers within HTTP requests. An
attacker could send an HTTP request from the client side with specially
crafted header Host header that bypasses same-origin security protections,
causing Squid operating as interception or reverse-proxy to contact the
wrong origin server. It could also be used for cache poisoning for client
not following RFC 7230. (CVE-2016-4554)

  * An incorrect reference counting flaw was found in the way Squid processes
ESI responses. If Squid is configured as reverse-proxy, for TLS/HTTPS
interception, an attacker controlling a server accessed by Squid, could
crash the squid worker, causing a Denial of Service attack. (CVE-2016-4556)" );
	script_tag( name: "affected", value: "squid on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1138" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-May/021896.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "squid", rpm: "squid~3.1.23~16.el6_8.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

