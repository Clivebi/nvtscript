if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882335" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-10 06:35:42 +0100 (Thu, 10 Dec 2015)" );
	script_cve_id( "CVE-2015-7981", "CVE-2015-8126", "CVE-2015-8472" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for libpng CESA-2015:2594 centos6" );
	script_tag( name: "summary", value: "Check the version of libpng" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libpng packages contain a library of
functions for creating and manipulating PNG (Portable Network Graphics) image
format files.

It was discovered that the png_get_PLTE() and png_set_PLTE() functions of
libpng did not correctly calculate the maximum palette sizes for bit depths
of less than 8. In case an application tried to use these functions in
combination with properly calculated palette sizes, this could lead to a
buffer overflow or out-of-bounds reads. An attacker could exploit this to
cause a crash or potentially execute arbitrary code by tricking an
unsuspecting user into processing a specially crafted PNG image. However,
the exact impact is dependent on the application using the library.
(CVE-2015-8126, CVE-2015-8472)

An array-indexing error was discovered in the png_convert_to_rfc1123()
function of libpng. An attacker could possibly use this flaw to cause an
out-of-bounds read by tricking an unsuspecting user into processing a
specially crafted PNG image. (CVE-2015-7981)

All libpng users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues." );
	script_tag( name: "affected", value: "libpng on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:2594" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-December/021517.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "libpng", rpm: "libpng~1.2.49~2.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpng-devel", rpm: "libpng-devel~1.2.49~2.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpng-static", rpm: "libpng-static~1.2.49~2.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

