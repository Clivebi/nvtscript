if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853127" );
	script_version( "2021-08-13T12:00:53+0000" );
	script_cve_id( "CVE-2016-5195", "CVE-2016-8859", "CVE-2017-1002101", "CVE-2018-1002105", "CVE-2018-16873", "CVE-2018-16874", "CVE-2019-10214" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-27 03:00:42 +0000 (Mon, 27 Apr 2020)" );
	script_name( "openSUSE: Security Advisory for kubernetes (openSUSE-SU-2020:0554-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0554-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00041.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kubernetes'
  package(s) announced via the openSUSE-SU-2020:0554-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update introduces kubernetes version 1.14.1 and cri-o 1.17.1 to Leap
  15.1.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-554=1" );
	script_tag( name: "affected", value: "'kubernetes' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "cri-o", rpm: "cri-o~1.17.1~lp151.2.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cri-o-kubeadm-criconfig", rpm: "cri-o-kubeadm-criconfig~1.17.1~lp151.2.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cri-tools", rpm: "cri-tools~1.18.0~lp151.2.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.14", rpm: "go1.14~1.14~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.14-doc", rpm: "go1.14-doc~1.14~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.14-race", rpm: "go1.14-race~1.14~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-apiserver", rpm: "kubernetes-apiserver~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-client", rpm: "kubernetes-client~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-controller-manager", rpm: "kubernetes-controller-manager~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-kubeadm", rpm: "kubernetes-kubeadm~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-kubelet-common", rpm: "kubernetes-kubelet-common~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-kubelet1.17", rpm: "kubernetes-kubelet1.17~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-kubelet1.18", rpm: "kubernetes-kubelet1.18~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-master", rpm: "kubernetes-master~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-node", rpm: "kubernetes-node~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-proxy", rpm: "kubernetes-proxy~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubernetes-scheduler", rpm: "kubernetes-scheduler~1.18.0~lp151.5.1", rls: "openSUSELeap15.1" ) )){
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

