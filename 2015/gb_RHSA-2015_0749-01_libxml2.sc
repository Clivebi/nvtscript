if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871346" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-31 07:09:15 +0200 (Tue, 31 Mar 2015)" );
	script_cve_id( "CVE-2014-0191" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for libxml2 RHSA-2015:0749-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libxml2 library is a development toolbox providing the implementation
of various XML standards.

It was discovered that libxml2 loaded external parameter entities even when
entity substitution was disabled. A remote attacker able to provide a
specially crafted XML file to an application linked against libxml2 could
use this flaw to conduct XML External Entity (XXE) attacks, possibly
resulting in a denial of service or an information leak on the system.
(CVE-2014-0191)

The CVE-2014-0191 issue was discovered by Daniel P. Berrange of Red Hat.

All libxml2 users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. The desktop must be
restarted (log out, then log back in) for this update to take effect." );
	script_tag( name: "affected", value: "libxml2 on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:0749-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-March/msg00054.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.9.1~5.el7_1.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-debuginfo", rpm: "libxml2-debuginfo~2.9.1~5.el7_1.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-devel", rpm: "libxml2-devel~2.9.1~5.el7_1.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.9.1~5.el7_1.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

