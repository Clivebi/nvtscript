if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854084" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2020-35503", "CVE-2020-35504", "CVE-2020-35505", "CVE-2020-35506", "CVE-2021-20255", "CVE-2021-3527", "CVE-2021-3682" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-17 17:29:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-21 03:01:42 +0000 (Sat, 21 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for qemu (openSUSE-SU-2021:2789-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2789-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UE3MLTPF62745SPUUDQR6ROYVP4GG6DT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the openSUSE-SU-2021:2789-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for qemu fixes the following issues:

     Security issues fixed:

  - usbredir: free call on invalid pointer in bufp_alloc (bsc#1189145,
       CVE-2021-3682)

  - NULL pointer dereference in ESP (bsc#1180433, CVE-2020-35504)
       (bsc#1180434, CVE-2020-35505) (bsc#1180435, CVE-2020-35506)

  - NULL pointer dereference issue in megasas-gen2 host bus adapter
       (bsc#1180432, CVE-2020-35503)

  - eepro100: stack overflow via infinite recursion (bsc#1182651,
       CVE-2021-20255)

  - usb: unbounded stack allocation in usbredir (bsc#1186012, CVE-2021-3527)" );
	script_tag( name: "affected", value: "'qemu' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390", rpm: "qemu-s390~4.2.1~11.28.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390-debuginfo", rpm: "qemu-s390-debuginfo~4.2.1~11.28.1", rls: "openSUSELeap15.3" ) )){
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
