import {
  addParticipant,
  removeMeeting,
  removeParticipant,
} from '../services/db.js'
import { encrypt } from '../helpers/crypto.js'
import {
  EVENT_MEETING_ENDED,
  EVENT_PARTICIPANT_JOINED,
  EVENT_PARTICIPANT_LEFT,
} from '../const.js'
import { createHmac } from 'node:crypto'

export default async function (fastify) {
  fastify.post('/hook', { undefined }, async (req, res) => {
    if (isValidZoomRequest(req)) {
      // webhook validation request from Zoom
      if (req.body?.event === 'endpoint.url_validation') {
        const hashForValidation = createHmac('sha256', process.env.SECRET_TOKEN)
          .update(req.body.payload.plainToken)
          .digest('hex')

        return res.send({
          plainToken: req.body.payload.plainToken,
          encryptedToken: hashForValidation,
        })
      }
    }

    const {
      event,
      payload: {
        object: { id: meeting_id, host_id, participant },
      },
    } = req.body

    if (event === EVENT_PARTICIPANT_JOINED) {
      await addParticipant(
        fastify.pg,
        meeting_id,
        host_id,
        participant.participant_user_id || participant.id,
        encrypt(participant.user_name)
      )
    }

    if (event === EVENT_PARTICIPANT_LEFT) {
      await removeParticipant(
        fastify.pg,
        meeting_id,
        participant.participant_user_id || participant.id,
        encrypt(participant.user_name)
      )
    }

    if (event === EVENT_MEETING_ENDED) {
      await removeMeeting(fastify.pg, meeting_id)
    }

    res.code(200).send()
  })
}

const isValidZoomRequest = request => {
  if (request.method !== 'POST') {
    return false
  }
  const message = `v0:${
    request.headers['x-zm-request-timestamp']
  }:${JSON.stringify(request.body)}`

  const hashForVerify = createHmac('sha256', process.env.SECRET_TOKEN)
    .update(message)
    .digest('hex')

  const signature = `v0=${hashForVerify}`

  return request.headers['x-zm-signature'] === signature
}
