if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882298" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-21 07:11:25 +0200 (Wed, 21 Oct 2015)" );
	script_cve_id( "CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for libwmf CESA-2015:1917 centos7" );
	script_tag( name: "summary", value: "Check the version of libwmf" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "libwmf is a library for reading and converting Windows Metafile Format
(WMF) vector graphics. libwmf is used by applications such as GIMP and
ImageMagick.

It was discovered that libwmf did not correctly process certain WMF
(Windows Metafiles) with embedded BMP images. By tricking a victim into
opening a specially crafted WMF file in an application using libwmf, a
remote attacker could possibly use this flaw to execute arbitrary code with
the privileges of the user running the application. (CVE-2015-0848,
CVE-2015-4588)

It was discovered that libwmf did not properly process certain WMF files.
By tricking a victim into opening a specially crafted WMF file in an
application using libwmf, a remote attacker could possibly exploit this
flaw to cause a crash or execute arbitrary code with the privileges of the
user running the application. (CVE-2015-4696)

It was discovered that libwmf did not properly process certain WMF files.
By tricking a victim into opening a specially crafted WMF file in an
application using libwmf, a remote attacker could possibly exploit this
flaw to cause a crash. (CVE-2015-4695)

All users of libwmf are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
update, all applications using libwmf must be restarted for the update to
take effect." );
	script_tag( name: "affected", value: "libwmf on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1917" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-October/021435.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "libwmf", rpm: "libwmf~0.2.8.4~41.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libwmf-devel", rpm: "libwmf-devel~0.2.8.4~41.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libwmf-lite", rpm: "libwmf-lite~0.2.8.4~41.el7_1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

