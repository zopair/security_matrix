#!/usr/bin/env python3
import json, subprocess, textwrap
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
R=Path(__file__).resolve().parents[1]; C=json.loads((R/"video/showcase.json").read_text()); O=R/"assets/marketing"; W=R/".showcase-build"
O.mkdir(parents=True,exist_ok=True); W.mkdir(parents=True,exist_ok=True)
FONT="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"; BOLD="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
A=tuple(C.get("accent",[90,160,240])); SIZE=(1280,720)
def run(a): subprocess.run(a,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
def card(title,body,i,n,path,end=False):
 im=Image.new("RGB",SIZE,(9,17,32)); d=ImageDraw.Draw(im,"RGBA")
 for x in range(0,1280,64): d.line((x,0,x,720),fill=(100,130,170,18))
 for y in range(0,720,64): d.line((0,y,1280,y),fill=(100,130,170,16))
 d.ellipse((900,-240,1480,340),outline=(*A,75),width=3); d.ellipse((1010,-140,1390,240),fill=(*A,16),outline=(*A,50),width=2)
 d.rounded_rectangle((72,58,650,104),18,fill=(*A,30),outline=(*A,110))
 d.text((92,70),C["tag"].upper(),font=ImageFont.truetype(BOLD,16),fill=(225,235,248))
 d.text((72,150),C["name"].upper(),font=ImageFont.truetype(BOLD,31),fill=(*A,255))
 if end: title="EXPLORE THE PROJECT ON GITHUB"; body=C["url"]
 else: d.text((1120,70),f"{i:02d} / {n:02d}",font=ImageFont.truetype(BOLD,20),fill=(175,193,215))
 y=250
 for line in textwrap.wrap(title.upper(),34):
  d.text((72,y),line,font=ImageFont.truetype(BOLD,48),fill=(248,250,253)); y+=62
 d.rounded_rectangle((72,500,1208,630),18,fill=(7,15,29,235),outline=(120,145,180,70))
 for j,line in enumerate(textwrap.wrap(body,90 if end else 105)[:3]):
  d.text((100,526+j*31),line,font=ImageFont.truetype(FONT,21),fill=(211,223,239))
 if end: d.text((100,585),"Aly Hussein Zopair  |  Project Overview",font=ImageFont.truetype(FONT,17),fill=(150,170,198))
 else:
  d.rounded_rectangle((72,665,1208,672),4,fill=(90,110,140,55)); d.rounded_rectangle((72,665,72+int(1136*i/n),672),4,fill=(*A,255))
 im.save(path)
clips=[]; scenes=C["scenes"]
for i,s in enumerate(scenes,1):
 img=W/f"s{i}.png"; wav=W/f"v{i}.wav"; mp4=W/f"c{i}.mp4"; card(s["title"],s["narration"],i,len(scenes),img)
 run(["espeak","-v","en-us+f3","-s","142","-p","43","-a","175","-w",str(wav),s["narration"]])
 dur=float(subprocess.check_output(["ffprobe","-v","error","-show_entries","format=duration","-of","csv=p=0",str(wav)]).decode().strip())+0.8
 run(["ffmpeg","-y","-loop","1","-i",str(img),"-i",str(wav),"-t",f"{dur:.2f}","-vf","scale=1280:720,format=yuv420p","-r","24","-c:v","libx264","-preset","ultrafast","-b:v","520k","-c:a","aac","-b:a","96k","-shortest",str(mp4)])
 clips.append(mp4)
img=W/"end.png"; end=W/"end.mp4"; card("","",len(scenes),len(scenes),img,True)
run(["ffmpeg","-y","-loop","1","-i",str(img),"-f","lavfi","-i","anullsrc=channel_layout=stereo:sample_rate=44100","-t","7","-vf","scale=1280:720,format=yuv420p","-r","24","-c:v","libx264","-preset","ultrafast","-b:v","520k","-c:a","aac","-b:a","96k","-shortest",str(end)])
clips.append(end); listing=W/"concat.txt"; listing.write_text("\n".join(f"file '{p.as_posix()}'" for p in clips)+"\n")
target=O/"project-overview.mp4"
run(["ffmpeg","-y","-f","concat","-safe","0","-i",str(listing),"-c:v","libx264","-preset","ultrafast","-b:v","520k","-maxrate","700k","-bufsize","1400k","-pix_fmt","yuv420p","-c:a","aac","-b:a","96k","-movflags","+faststart",str(target)])
print(f"Rendered {target} ({target.stat().st_size} bytes)")
