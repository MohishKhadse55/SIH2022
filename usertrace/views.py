import datetime
import requests
import socket

from allauth.socialaccount.models import SocialAccount
from django.contrib import messages
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.models import User
from django.shortcuts import render, redirect

# Create your views here.
from usertrace.models import UserData

organisation = "vit.edu"
meetinglink = "https://meet.google.com/ezo-cjyn-gou"


def home(request):
    if request.method == "POST":
        # authenticated
        try:
            social_accounts = SocialAccount.objects.get(user=request.user)
        except SocialAccount.DoesNotExist:
            return redirect('/logout')
        name = social_accounts.extra_data["name"]
        email = social_accounts.extra_data["email"]
        profile_image = social_accounts.extra_data["picture"]
        url = meetinglink
        try:
            org = social_accounts.extra_data["hd"]
        except KeyError:
            org = "None"
        #     load IP tracing module
        ip_data = visitor_ip_address(request, name, email, profile_image, url, org)
        ip_data.save()
        return redirect(url)
    return render(request, 'homepage.html')


def sign_out(request):
    logout(request)
    return redirect('/')


def signin(request):
    if request.user.is_authenticated:
        if not request.user.has_usable_password():
            return redirect("/logout")
        return redirect("/dash")
    if request.method == "POST":
        # validate user login details
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            request.session["login_status"] = True
            return redirect('/dash')
        else:
            print("err")
            messages.info(request, "User Credentials Not Match")
            request.session["login_status"] = False
            return render(request, 'login.html')
    else:
        return render(request, 'login.html')


def register(request):
    if request.user.is_authenticated:
        return redirect("/dash")
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        name = request.POST["name"]
        f_name = name.split(' ')[0]
        try:
            l_name = name.split(' ')[1]
        except IndexError:
            l_name = ""
        email = request.POST["email"]
        # contact = request.POST["contact"]
        confpassword = request.POST["confpassword"]
        if password == confpassword:
            user = User.objects.create_user(username=username,
                                            email=email,
                                            password=password,
                                            first_name=f_name,
                                            last_name=l_name, )
            user.save()
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                request.session["login_status"] = True
                return redirect('/dash')
            else:
                print("err")
                messages.info(request, "User Credentials Not Match")
                request.session["login_status"] = False
                return render(request, 'login.html')
        else:
            messages.info(request, "Passwords not match")

    return render(request, 'registration.html')


def dash(request):
    if request.user.is_authenticated:
        if not request.user.has_usable_password():
            return redirect("/logout")
        # user is login
        meeting_link = meetinglink
        org = organisation
        author = request.user.first_name + " " + request.user.last_name
        ip_details = UserData.objects.all().order_by('-unidentified')
        total_ip = len(ip_details)
        out_of_org = 0
        for ipdetail in ip_details:
            if ipdetail.org != "vit.edu":
                out_of_org += 1
        return render(request, 'admin_meet_details.html',
                      {'meeting_link': meeting_link, 'org': org, 'author': author, 'ip_details': ip_details,
                       'total_record': total_ip, 'out_of_org': out_of_org})
    else:
        print("login failed")
        return redirect("/signin")


def user_details(request):
    if request.method == "POST":
        if not request.user.has_usable_password():
            return redirect("/logout")
        uid = request.POST["recordid"]
        details = UserData.objects.get(id=uid)
        return render(request, 'userdata.html', {'userdetails': details})
    else:
        return redirect('/dash')


def visitor_ip_address(request, name, email, profile_image, url, org):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    if "." in ip:
        try:
            port = ip.split(":")[1]
        except IndexError:
            port = "80"
        ip = ip.split(":")[0]
    else:
        port = request.META.get('REMOTE_PORT')
    protocol = request.META.get('SERVER_PROTOCOL')
    agent = request.META.get('HTTP_USER_AGENT')
    referer = request.META.get('HTTP_REFERER')
    unidentified = False
    if org != organisation:
        unidentified = True
    try:
        socket.inet_aton(ip)
        ip_valid = True
    except socket.error:
        ip_valid = False
    ip_data = UserData(ip=ip, port=port, protocol=protocol, agent=agent, referer=referer, validIp=ip_valid, name=name,
                       email_id=email, profile_image=profile_image, date=datetime.date.today(), meeting_url=url,
                       org=org, unidentified=unidentified, )
    ip_data = ipInfo(ip, ip_data)
    return ip_data


def ipInfo(addr, ip_data):
    response = requests.get("http://ip-api.com/json/" + addr).json()
    if response["status"] == "success":
        ip_data.locStatus = True
        ip_data.country = response["country"]
        ip_data.countryCode = response["countryCode"]
        ip_data.region = response["region"]
        ip_data.regionName = response["regionName"]
        ip_data.city = response["city"]
        ip_data.zip = response["zip"]
        ip_data.lat = response["lat"]
        ip_data.lon = response["lon"]
        ip_data.timezone = response["timezone"]
        ip_data.isp = response["isp"]
        ip_data.ip_org = response["org"]
        ip_data.orgAs = response["as"]
    return ip_data
