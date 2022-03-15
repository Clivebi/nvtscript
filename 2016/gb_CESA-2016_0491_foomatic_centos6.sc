if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882436" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-24 06:15:07 +0100 (Thu, 24 Mar 2016)" );
	script_cve_id( "CVE-2010-5325", "CVE-2015-8327", "CVE-2015-8560" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for foomatic CESA-2016:0491 centos6" );
	script_tag( name: "summary", value: "Check the version of foomatic" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Foomatic is a comprehensive,
spooler-independent database of printers, printer drivers, and driver
descriptions. The package also includes spooler-independent command line
interfaces to manipulate queues and to print files and manipulate print jobs.

It was discovered that the unhtmlify() function of foomatic-rip did not
correctly calculate buffer sizes, possibly leading to a heap-based memory
corruption. A malicious attacker could exploit this flaw to cause
foomatic-rip to crash or, possibly, execute arbitrary code.
(CVE-2010-5325)

It was discovered that foomatic-rip failed to remove all shell special
characters from inputs used to construct command lines for external
programs run by the filter. An attacker could possibly use this flaw to
execute arbitrary commands. (CVE-2015-8327, CVE-2015-8560)

All foomatic users should upgrade to this updated package, which contains
backported patches to correct these issues." );
	script_tag( name: "affected", value: "foomatic on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0491" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-March/021768.html" );
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
	if(( res = isrpmvuln( pkg: "foomatic", rpm: "foomatic~4.0.4~5.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

