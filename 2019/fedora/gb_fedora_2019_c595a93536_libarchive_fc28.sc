if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875549" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2018-1000877", "CVE-2018-1000878", "CVE-2018-1000879", "CVE-2018-1000880", "CVE-2019-1000019", "CVE-2019-1000020" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-06 01:15:00 +0000 (Wed, 06 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-04-05 02:08:21 +0000 (Fri, 05 Apr 2019)" );
	script_name( "Fedora Update for libarchive FEDORA-2019-c595a93536" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-c595a93536" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CBOCC2M6YGPZA6US43YK4INPSJZZHRTG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'libarchive' package(s) announced via the FEDORA-2019-c595a93536 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Libarchive is a programming library that can
  create and read several different streaming archive formats, including most
  popular tar variants, several cpio formats, and both BSD and GNU ar variants.
  It can also write shar archives and read ISO9660 CDROM images and ZIP archives." );
	script_tag( name: "affected", value: "'libarchive' package(s) on Fedora 28." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "libarchive", rpm: "libarchive~3.3.3~6.fc28", rls: "FC28" ) )){
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

