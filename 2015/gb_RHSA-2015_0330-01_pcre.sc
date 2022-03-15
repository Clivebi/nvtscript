if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871333" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-06 06:50:49 +0100 (Fri, 06 Mar 2015)" );
	script_cve_id( "CVE-2014-8964" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for pcre RHSA-2015:0330-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pcre'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PCRE is a Perl-compatible regular expression library.

A flaw was found in the way PCRE handled certain malformed regular
expressions. This issue could cause an application (for example, Konqueror)
linked against PCRE to crash while parsing malicious regular expressions.
(CVE-2014-8964)

This update also adds the following enhancement:

  * Support for the little-endian variant of IBM Power Systems has been added
to the pcre packages. (BZ#1123498, BZ#1125642)

All pcre users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue and add this enhancement." );
	script_tag( name: "affected", value: "pcre on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:0330-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-March/msg00020.html" );
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
	if(( res = isrpmvuln( pkg: "pcre", rpm: "pcre~8.32~14.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pcre-debuginfo", rpm: "pcre-debuginfo~8.32~14.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pcre-devel", rpm: "pcre-devel~8.32~14.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

