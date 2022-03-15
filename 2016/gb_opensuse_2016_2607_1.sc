if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851419" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-10-25 05:54:04 +0200 (Tue, 25 Oct 2016)" );
	script_cve_id( "CVE-2016-7568" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for gd (openSUSE-SU-2016:2607-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gd'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gd fixes the following issue:

  - CVE-2016-7568: Integer overflow in the gdImageWebpCtx function in
  gd_webp.c (libgd) (bsc#1001900)." );
	script_tag( name: "affected", value: "gd on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:2607-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "gd", rpm: "gd~2.1.0~7.19.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gd-debuginfo", rpm: "gd-debuginfo~2.1.0~7.19.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gd-debugsource", rpm: "gd-debugsource~2.1.0~7.19.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gd-devel", rpm: "gd-devel~2.1.0~7.19.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgd3", rpm: "libgd3~2.1.0~7.19.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgd3-debuginfo", rpm: "libgd3-debuginfo~2.1.0~7.19.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgd3-32bit", rpm: "libgd3-32bit~2.1.0~7.19.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgd3-debuginfo-32bit", rpm: "libgd3-debuginfo-32bit~2.1.0~7.19.1", rls: "openSUSE13.2" ) )){
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

