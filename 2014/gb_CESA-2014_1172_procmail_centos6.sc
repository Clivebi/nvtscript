if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882022" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-11 05:58:30 +0200 (Thu, 11 Sep 2014)" );
	script_cve_id( "CVE-2014-3618" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for procmail CESA-2014:1172 centos6" );
	script_tag( name: "insight", value: "The procmail program is used for local
mail delivery. In addition to just delivering mail, procmail can be used for
automatic filtering, presorting, and other mail handling jobs.

A heap-based buffer overflow flaw was found in procmail's formail utility.
A remote attacker could send an email with specially crafted headers that,
when processed by formail, could cause procmail to crash or, possibly,
execute arbitrary code as the user running formail. (CVE-2014-3618)

All procmail users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue." );
	script_tag( name: "affected", value: "procmail on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:1172" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-September/020550.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'procmail'
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
	if(( res = isrpmvuln( pkg: "procmail", rpm: "procmail~3.22~25.1.el6_5.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

