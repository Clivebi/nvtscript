if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854163" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2021-30475" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-17 16:40:00 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-09-15 01:01:47 +0000 (Wed, 15 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for libaom (openSUSE-SU-2021:1254-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1254-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/X2RSNQSM4KBVYVR4O53XXM7IY2AXF6OC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libaom'
  package(s) announced via the openSUSE-SU-2021:1254-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libaom fixes the following issues:

  - CVE-2021-30475: Fixed buffer overflow in aom_dsp/noise_model.c
       (bsc#1189497).

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'libaom' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "aom-tools", rpm: "aom-tools~1.0.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aom-tools-debuginfo", rpm: "aom-tools-debuginfo~1.0.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaom-debugsource", rpm: "libaom-debugsource~1.0.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaom-devel", rpm: "libaom-devel~1.0.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaom0", rpm: "libaom0~1.0.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaom0-debuginfo", rpm: "libaom0-debuginfo~1.0.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaom0-32bit", rpm: "libaom0-32bit~1.0.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaom0-32bit-debuginfo", rpm: "libaom0-32bit-debuginfo~1.0.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaom-devel-doc", rpm: "libaom-devel-doc~1.0.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
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

