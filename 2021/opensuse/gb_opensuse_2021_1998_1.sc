if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853917" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2021-3565" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-30 05:15:00 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:03:10 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for tpm2.0-tools (openSUSE-SU-2021:1998-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1998-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FABT25LIO7DOQ34GM7NCGQ5RVCTZMIJV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tpm2.0-tools'
  package(s) announced via the openSUSE-SU-2021:1998-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tpm2.0-tools fixes the following issues:

  - CVE-2021-3565: Fixed issue when no encrypted session with the TPM is
       used (bsc#1186490)." );
	script_tag( name: "affected", value: "'tpm2.0-tools' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "tpm2.0-tools", rpm: "tpm2.0-tools~4.3.0~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tpm2.0-tools-debuginfo", rpm: "tpm2.0-tools-debuginfo~4.3.0~4.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tpm2.0-tools-debugsource", rpm: "tpm2.0-tools-debugsource~4.3.0~4.3.1", rls: "openSUSELeap15.3" ) )){
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

