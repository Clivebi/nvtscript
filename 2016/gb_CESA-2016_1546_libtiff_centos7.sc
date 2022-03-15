if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882532" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-08 15:11:57 +0530 (Mon, 08 Aug 2016)" );
	script_cve_id( "CVE-2014-8127", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9330", "CVE-2014-9655", "CVE-2015-1547", "CVE-2015-7554", "CVE-2015-8665", "CVE-2015-8668", "CVE-2015-8683", "CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2015-8784", "CVE-2016-3632", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5320" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for libtiff CESA-2016:1546 centos7" );
	script_tag( name: "summary", value: "Check the version of libtiff" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libtiff packages contain a library of
functions for manipulating Tagged Image File Format (TIFF) files.

Security Fix(es):

  * Multiple flaws have been discovered in libtiff. A remote attacker could
exploit these flaws to cause a crash or memory corruption and, possibly,
execute arbitrary code by tricking an application linked against libtiff
into processing specially crafted files. (CVE-2014-9655, CVE-2015-1547,
CVE-2015-8784, CVE-2015-8683, CVE-2015-8665, CVE-2015-8781, CVE-2015-8782,
CVE-2015-8783, CVE-2016-3990, CVE-2016-5320)

  * Multiple flaws have been discovered in various libtiff tools (bmp2tiff,
pal2rgb, thumbnail, tiff2bw, tiff2pdf, tiffcrop, tiffdither, tiffsplit,
tiff2rgba). By tricking a user into processing a specially crafted file, a
remote attacker could exploit these flaws to cause a crash or memory
corruption and, possibly, execute arbitrary code with the privileges of the
user running the libtiff tool. (CVE-2014-8127, CVE-2014-8129,
CVE-2014-8130, CVE-2014-9330, CVE-2015-7554, CVE-2015-8668, CVE-2016-3632,
CVE-2016-3945, CVE-2016-3991)" );
	script_tag( name: "affected", value: "libtiff on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1546" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-August/022010.html" );
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
	if(( res = isrpmvuln( pkg: "libtiff", rpm: "libtiff~4.0.3~25.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~4.0.3~25.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-static", rpm: "libtiff-static~4.0.3~25.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-tools", rpm: "libtiff-tools~4.0.3~25.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

