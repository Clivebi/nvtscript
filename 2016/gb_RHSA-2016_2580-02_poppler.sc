if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871709" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-04 05:43:36 +0100 (Fri, 04 Nov 2016)" );
	script_cve_id( "CVE-2015-8868" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for poppler RHSA-2016:2580-02" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Poppler is a Portable Document Format (PDF)
rendering library, used by applications such as Evince.

Security Fix(es):

  * A heap-buffer overflow was found in the poppler library. An attacker
could create a malicious PDF file that would cause applications that use
poppler (such as Evince) to crash or, potentially, execute arbitrary code
when opened. (CVE-2015-8868)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section." );
	script_tag( name: "affected", value: "poppler on
  Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:2580-02" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-November/msg00016.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "poppler", rpm: "poppler~0.26.5~16.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "poppler-debuginfo", rpm: "poppler-debuginfo~0.26.5~16.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "poppler-glib", rpm: "poppler-glib~0.26.5~16.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "poppler-qt", rpm: "poppler-qt~0.26.5~16.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "poppler-utils", rpm: "poppler-utils~0.26.5~16.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

