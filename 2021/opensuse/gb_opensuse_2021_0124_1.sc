if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853736" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686", "CVE-2020-25687" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 18:22:00 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:02:20 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for dnsmasq (openSUSE-SU-2021:0124-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0124-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GY5KV2WHBZG4XCWVKZOU4DFCHSMBT5KV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the openSUSE-SU-2021:0124-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dnsmasq fixes the following issues:

  - bsc#1177077: Fixed DNSpooq vulnerabilities

  - CVE-2020-25684, CVE-2020-25685, CVE-2020-25686: Fixed multiple Cache
       Poisoning attacks.

  - CVE-2020-25681, CVE-2020-25682, CVE-2020-25683, CVE-2020-25687: Fixed
       multiple potential Heap-based overflows when DNSSEC is enabled.

  - Retry query to other servers on receipt of SERVFAIL rcode (bsc#1176076)

     This update was imported from the SUSE:SLE-15-SP1:Update update project." );
	script_tag( name: "affected", value: "'dnsmasq' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "dnsmasq", rpm: "dnsmasq~2.78~lp152.7.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dnsmasq-debuginfo", rpm: "dnsmasq-debuginfo~2.78~lp152.7.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dnsmasq-debugsource", rpm: "dnsmasq-debugsource~2.78~lp152.7.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dnsmasq-utils", rpm: "dnsmasq-utils~2.78~lp152.7.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dnsmasq-utils-debuginfo", rpm: "dnsmasq-utils-debuginfo~2.78~lp152.7.3.1", rls: "openSUSELeap15.2" ) )){
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

