if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850631" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-01-29 05:13:05 +0100 (Thu, 29 Jan 2015)" );
	script_cve_id( "CVE-2014-9495", "CVE-2015-0973" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "openSUSE: Security Advisory for libpng16 (openSUSE-SU-2015:0161-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpng16'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libpng was updated to fix some security issues:

  * CVE-2014-9495 [bnc#912076]: Heap-buffer overflow png_combine_row() with
  very wide interlaced images

  * CVE-2015-0973 [bnc#912929]: overflow in png_read_IDAT_data

  libpng is now also build with -DPNG_SAFE_LIMITS_SUPPORTED." );
	script_tag( name: "affected", value: "libpng16 on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:0161-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.1" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16", rpm: "libpng16-16~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16-debuginfo", rpm: "libpng16-16-debuginfo~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-compat-devel", rpm: "libpng16-compat-devel~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-debugsource", rpm: "libpng16-debugsource~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-devel", rpm: "libpng16-devel~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-tools", rpm: "libpng16-tools~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-tools-debuginfo", rpm: "libpng16-tools-debuginfo~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16-32bit", rpm: "libpng16-16-32bit~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16-debuginfo-32bit", rpm: "libpng16-16-debuginfo-32bit~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-compat-devel-32bit", rpm: "libpng16-compat-devel-32bit~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-devel-32bit", rpm: "libpng16-devel-32bit~1.6.6~16.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

