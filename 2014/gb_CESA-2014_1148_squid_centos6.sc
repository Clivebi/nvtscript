if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881996" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-04 05:58:07 +0200 (Thu, 04 Sep 2014)" );
	script_cve_id( "CVE-2013-4115", "CVE-2014-3609" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for squid CESA-2014:1148 centos6" );
	script_tag( name: "insight", value: "Squid is a high-performance proxy caching
server for web clients, supporting FTP, Gopher, and HTTP data objects.

A flaw was found in the way Squid handled malformed HTTP Range headers.
A remote attacker able to send HTTP requests to the Squid proxy could use
this flaw to crash Squid. (CVE-2014-3609)

A buffer overflow flaw was found in Squid's DNS lookup module. A remote
attacker able to send HTTP requests to the Squid proxy could use this flaw
to crash Squid. (CVE-2013-4115)

Red Hat would like to thank the Squid project for reporting the
CVE-2014-3609 issue. Upstream acknowledges Matthew Daley as the original
reporter.

All Squid users are advised to upgrade to this updated package, which
contains backported patches to correct these issues. After installing this
update, the squid service will be restarted automatically." );
	script_tag( name: "affected", value: "squid on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:1148" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-September/020534.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "squid", rpm: "squid~3.1.10~22.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

