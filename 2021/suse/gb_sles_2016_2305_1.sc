if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2305.1" );
	script_cve_id( "CVE-2015-4141", "CVE-2015-4142", "CVE-2015-4143", "CVE-2015-5310", "CVE-2015-8041" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-22 02:29:00 +0000 (Thu, 22 Feb 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2305-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2305-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162305-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wpa_supplicant' package(s) announced via the SUSE-SU-2016:2305-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wpa_supplicant fixes the following issues:
- CVE-2015-4141: WPS UPnP vulnerability with HTTP chunked transfer
 encoding. (bnc#930077)
- CVE-2015-4142: Integer underflow in AP mode WMM Action frame
 processing. (bnc#930078)
- CVE-2015-4143: EAP-pwd missing payload length validation. (bnc#930079)
- CVE-2015-5310: Ignore Key Data in WNM Sleep Mode Response frame if no
 PMF in use. (bsc#952254)
- CVE-2015-8041: Fix payload length validation in NDEF record parser.
 (bsc#937419)" );
	script_tag( name: "affected", value: "'wpa_supplicant' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant", rpm: "wpa_supplicant~2.2~14.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-debuginfo", rpm: "wpa_supplicant-debuginfo~2.2~14.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wpa_supplicant-debugsource", rpm: "wpa_supplicant-debugsource~2.2~14.2", rls: "SLES12.0SP1" ) )){
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

