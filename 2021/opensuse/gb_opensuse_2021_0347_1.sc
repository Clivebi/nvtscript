if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853643" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2020-28243", "CVE-2020-28972", "CVE-2020-35662", "CVE-2021-25281", "CVE-2021-25282", "CVE-2021-25283", "CVE-2021-25284", "CVE-2021-3144", "CVE-2021-3148", "CVE-2021-3197" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-01 17:15:00 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:58:00 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for salt (openSUSE-SU-2021:0347-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0347-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CYH7ONK65HNBANHLED5R64OBSM2EORYI" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'salt'
  package(s) announced via the openSUSE-SU-2021:0347-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for salt fixes the following issues:

  - Fix regression on cmd.run when passing tuples as cmd (bsc#1182740)

  - Allow `extra_filerefs` as sanitized `kwargs` for SSH client

  - Fix errors with virt.update

  - Fix for multiple for security issues (CVE-2020-28243) (CVE-2020-28972)
       (CVE-2020-35662) (CVE-2021-3148) (CVE-2021-3144) (CVE-2021-25281)
       (CVE-2021-25282) (CVE-2021-25283) (CVE-2021-25284) (CVE-2021-3197)
       (bsc#1181550) (bsc#1181556) (bsc#1181557) (bsc#1181558) (bsc#1181559)
       (bsc#1181560) (bsc#1181561) (bsc#1181562) (bsc#1181563) (bsc#1181564)
       (bsc#1181565)

  - virt: search for `grub.xen` path

  - Xen spicevmc, DNS SRV records backports:

  - Fix virtual network generated DNS XML for SRV records

  - Don&#x27 t add spicevmc channel to xen VMs

  - virt UEFI fix: virt.update when `efi=True`

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'salt' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "salt-bash-completion", rpm: "salt-bash-completion~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-fish-completion", rpm: "salt-fish-completion~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-zsh-completion", rpm: "salt-zsh-completion~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-salt", rpm: "python2-salt~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-salt", rpm: "python3-salt~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt", rpm: "salt~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-api", rpm: "salt-api~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-cloud", rpm: "salt-cloud~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-doc", rpm: "salt-doc~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-master", rpm: "salt-master~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-minion", rpm: "salt-minion~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-proxy", rpm: "salt-proxy~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-ssh", rpm: "salt-ssh~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-standalone-formulas-configuration", rpm: "salt-standalone-formulas-configuration~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-syndic", rpm: "salt-syndic~3000~lp152.3.27.1", rls: "openSUSELeap15.2" ) )){
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

