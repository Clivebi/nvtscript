if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853702" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2020-26217", "CVE-2020-26258", "CVE-2020-26259" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:00:28 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for xstream (openSUSE-SU-2021:0140-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0140-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CTO6QRFLVKVHOYBP6VLJP4KZXZFZSKET" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xstream'
  package(s) announced via the openSUSE-SU-2021:0140-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xstream fixes the following issues:

     xstream was updated to version 1.4.15.

  - CVE-2020-26217: Fixed a remote code execution due to insecure XML
       deserialization when relying on blocklists (bsc#1180994).

  - CVE-2020-26258: Fixed a server-side request forgery vulnerability
       (bsc#1180146).

  - CVE-2020-26259: Fixed an arbitrary file deletion vulnerability
       (bsc#1180145).

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'xstream' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "xstream", rpm: "xstream~1.4.15~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xstream-benchmark", rpm: "xstream-benchmark~1.4.15~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xstream-javadoc", rpm: "xstream-javadoc~1.4.15~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xstream-parent", rpm: "xstream-parent~1.4.15~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

